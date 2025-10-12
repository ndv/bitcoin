#include <addresstype.h>
#include <common/args.h>
#include <compat/byteswap.h>
#include <index/addrindex.h>
#include <kernel/cs_main.h>
#include <logging.h>
#include <sync.h>
#include <undo.h>
#include <validation.h>

#include <memory>
#include <variant>

#include <atomic>
#include <node/database_args.h>
#include <thread>
#include <condition_variable>
#include <mutex>

using namespace std;

unique_ptr<AddressIndex> g_address_index;

constexpr int first_bin_height = 300000;
constexpr int bin_height_interval = 20000;

uint8_t GetBinNumber(int height)
{
    if (height < first_bin_height) return 0;
    return (height - first_bin_height) / bin_height_interval + 1;
}

AddressIndex::DB::DB(size_t n_cache_size, bool f_memory, bool f_wipe) : BaseIndex::DB(gArgs.GetDataDirNet() / "indexes" / "addrindex", n_cache_size, f_memory, f_wipe, false)
{
}

AddressIndex::AddressIndex(std::unique_ptr<interfaces::Chain> chain, size_t n_cache_size, bool f_memory, bool f_wipe)
    : BaseIndex(std::move(chain), "addressindex")
{
    m_db = make_unique<AddressIndex::DB>(n_cache_size, f_memory, f_wipe);
    m_height = GetSummary().best_block_height;
}

BaseIndex::DB& AddressIndex::GetDB() const
{
    return *m_db;
}

optional<AddressKey> AddressIndex::GetAddressKey(const CTxDestination& addr, uint8_t bin)
{
    AddressKey key;
    const uint8_t* data = nullptr;

    if (const auto pkHash(get_if<PKHash>(&addr)); pkHash) {
        data = pkHash->data();
    }
    if (const auto scriptHash(get_if<ScriptHash>(&addr)); scriptHash) {
        data = scriptHash->data();
    }
    if (const auto wHash(get_if<WitnessV0KeyHash>(&addr)); wHash) {
        data = wHash->data();
    }
    if (const auto wHash(get_if<WitnessV0ScriptHash>(&addr)); wHash) {
        data = wHash->data();
    }
    if (const auto wHash(get_if<WitnessV1Taproot>(&addr)); wHash) {
        data = wHash->data();
    }

    if (data) {
        key.key = ReadBE64(data);
        key.bin = bin;
        return key;
    } else {
        return nullopt;
    }
}

void AddressIndex::addScriptToAccumulatedChanges(const CScript& script, const CTransactionRef& tx, uint8_t bin)
{
    if (script.empty() || script[0] == OP_RETURN) return;

    CTxDestination address;
    if (ExtractDestination(script, address)) {
        auto k = GetAddressKey(address, bin);
        if (k.has_value()) {
            if (m_accumulated_changes.find(k.value()) == m_accumulated_changes.end()) {
                // load the existing data from the database
                m_accumulated_changes[k.value()] = Read(k.value()).value_or(AddressData{});
            }
            m_accumulated_changes[k.value()].push_back(tx->GetHash());
        }
    }
}

void AddressIndex::popScriptFromAccumulatedChanges(const CScript& script, const CTransactionRef& tx, uint8_t bin)
{
    if (script.empty() || script[0] == OP_RETURN) return;

    CTxDestination address;
    if (ExtractDestination(script, address)) {
        auto k = GetAddressKey(address, bin);
        if (k.has_value()) {
            if (m_accumulated_changes.find(k.value()) == m_accumulated_changes.end()) {
                // load the existing data from the database
                m_accumulated_changes[k.value()] = Read(k.value()).value_or(AddressData{});
            }
            auto& v = m_accumulated_changes[k.value()];
            if (v.empty())
                LogError("Unexpected empty transaction list in popScriptFromAccumulatedChanges");
            else if (v.back() != tx->GetHash())
                LogError("Error popping a script from accumulated changes: no matching tx found");
            else
                v.pop_back();
        }
    }
}

bool AddressIndex::CustomAppend(const interfaces::BlockInfo& block_info)
{
    // transaction inputs are already collected in the CBlockUndo
    // no need to query the database
    CBlockUndo block_undo;

    if (block_info.height > 0) {
        // pindex variable gives indexing code access to node internals. It
        // will be removed in upcoming commit
        const CBlockIndex* pindex = WITH_LOCK(cs_main, return m_chainstate->m_blockman.LookupBlockIndex(block_info.hash));
        if (!m_chainstate->m_blockman.UndoReadFromDisk(block_undo, *pindex)) {
            return false;
        }
    }

    uint8_t bin_number = GetBinNumber(block_info.height);

    const CBlock& block = *Assert(block_info.data);

    lock_guard<recursive_mutex> l(m_mutex);

    for (size_t i = 0; i < block.vtx.size(); i++) {
        const CTransactionRef& tx = block.vtx[i];

        std::set<CScript> scripts;

        for (const CTxOut& txout : tx->vout) {
            const CScript& script = txout.scriptPubKey;

            if (scripts.contains(script)) continue;
            scripts.insert(script);

            addScriptToAccumulatedChanges(script, tx, bin_number);

        }

        if (i > 0) {
            const CTxUndo& tx_undo = block_undo.vtxundo[i - 1];
            for (const Coin& prevout : tx_undo.vprevout) {
                const CScript& script = prevout.out.scriptPubKey;
                if (script.empty()) continue;

                if (scripts.contains(script)) continue;
                scripts.insert(script);

                addScriptToAccumulatedChanges(script, tx, bin_number);
            }
        }
    }

    return BaseIndex::CustomAppend(block_info);
}

void AddressIndex::RewindBlock(const CBlock& block, const CBlockIndex* block_index)
{
    CBlockUndo block_undo;

    if (block_index->nHeight > 0) {
        // pindex variable gives indexing code access to node internals. It
        // will be removed in upcoming commit
        const CBlockIndex* pindex = WITH_LOCK(cs_main, return m_chainstate->m_blockman.LookupBlockIndex(block_index->GetBlockHash()));
        if (!m_chainstate->m_blockman.UndoReadFromDisk(block_undo, *pindex)) {
            return;
        }
    }

    uint8_t bin_number = GetBinNumber(block_index->nHeight);

    // same as in CustomAppend, but in reverse order
    for (int i = (int)block.vtx.size() - 1; i >= 0; i--) {
        const CTransactionRef& tx = block.vtx[i];

        std::set<CScript> scripts;

        if (i > 0) {
            const CTxUndo& tx_undo = block_undo.vtxundo[i - 1];
            for (auto it = tx_undo.vprevout.crbegin(); it != tx_undo.vprevout.crend(); it++) {

                if (scripts.contains(it->out.scriptPubKey)) continue;
                scripts.insert(it->out.scriptPubKey);

                popScriptFromAccumulatedChanges(it->out.scriptPubKey, tx, bin_number);
            }
        }

        for (auto it = tx->vout.crbegin(); it != tx->vout.crend(); it++) {
            const CTxOut& txout = *it;

            if (scripts.contains(txout.scriptPubKey)) continue;
            scripts.insert(txout.scriptPubKey);

            popScriptFromAccumulatedChanges(txout.scriptPubKey, tx, bin_number);
        }

    }
}

bool AddressIndex::CustomRewind(const interfaces::BlockRef& current_tip, const interfaces::BlockRef& new_tip)
{
    {
        LOCK(cs_main);
        const CBlockIndex* iter_idx{m_chainstate->m_blockman.LookupBlockIndex(current_tip.hash)};
        const CBlockIndex* new_idx{m_chainstate->m_blockman.LookupBlockIndex(new_tip.hash)};

        lock_guard<recursive_mutex> l(m_mutex);

        do {
            CBlock block;

            if (!m_chainstate->m_blockman.ReadBlockFromDisk(block, *Assert(iter_idx))) {
                LogError("%s: Failed to read block %s from disk",
                             __func__, iter_idx->GetBlockHash().ToString());
                return false;
            }

            RewindBlock(block, iter_idx);

            iter_idx = iter_idx->GetAncestor(iter_idx->nHeight - 1);
        } while (new_idx->nHeight != iter_idx->nHeight);
    }

    return BaseIndex::CustomRewind(current_tip, new_tip);
}

bool AddressIndex::CustomCommit(CDBBatch& batch)
{
    for (const auto& [addr, val] : m_accumulated_changes) {
        batch.Write(addr, val);
    }
    m_accumulated_changes.clear();

    return m_db->WriteBatch(batch);
}

optional<AddressIndex::AddressData> AddressIndex::operator[](const AddressKey& key) const
{
    if (auto const & entry = m_accumulated_changes.find(key); entry != m_accumulated_changes.end()) {
        return entry->second;
    }
    return Read(key);
}

optional<AddressIndex::AddressData> AddressIndex::Read(const AddressKey& key) const
{
    AddressData v;
    if (m_db->Read(key, v)) return v;
    return std::nullopt;
}

struct AddressDBIterator {
    CDBIterator* m_dbit;

    // fetched data
    AddressKey m_key;
    std::vector<Txid> m_tx_ids;

    AddressDBIterator(CDBIterator* dbit, uint64_t key) : m_dbit(dbit), m_key(key)
    {
        AddressKey akey{key, 0};

        dbit->Seek(akey);
        if (dbit->Valid()) {
            dbit->GetKey(akey);
            m_key = akey;
            dbit->GetValue(m_tx_ids);
        }
    }

    ~AddressDBIterator()
    {
        delete m_dbit;
    }

    operator bool() const
    {
        return m_dbit->Valid();
    }

    AddressKey GetKey()
    {
        return m_key;
    }

    std::vector<Txid>* GetValue()
    {
        return &m_tx_ids;
    }

    void Next()
    {
        m_dbit->Next();
        if (m_dbit->Valid()) {
            AddressKey akey;
            m_dbit->GetKey(akey);
            m_key = akey;
            m_dbit->GetValue(m_tx_ids);
        }
    }
};

struct AddressCacheIterator {
    using MapType = std::map<AddressKey, AddressIndex::AddressData>;
    std::map<AddressKey, AddressIndex::AddressData> m_cache;
    MapType::iterator m_it;

    AddressCacheIterator(std::map<AddressKey, AddressIndex::AddressData> cache, uint64_t key)
        : m_cache(std::move(cache))
    {
        m_it = m_cache.find(AddressKey{key, 0});
    }

    operator bool() const
    {
        return m_it != m_cache.end();
    }

    AddressKey GetKey()
    {
        return m_it->first;
    }

    std::vector<Txid>* GetValue()
    {
        return &m_it->second;
    }

    void Next()
    {
        m_it++;
    }
};

int AddressIndex::GetNBins() const
{
    auto sum = GetSummary();
    if (sum.best_block_height < first_bin_height) return 1;
    return (sum.best_block_height - first_bin_height) / bin_height_interval + 1;
}


// merge db and cache data

AddressIndexIterator::operator bool() const
{
    if (m_pos < m_current_data->size())
        return true;
    else
        return
            *static_cast<AddressDBIterator*>(m_db_iterator) ||
            *static_cast<AddressCacheIterator*>(m_cache_iterator);
}

uint64_t AddressIndexIterator::GetKey()
{
    return m_current_key.key;
}

Txid& AddressIndexIterator::GetValue()
{
    return (*m_current_data)[m_pos++];
}

void AddressIndexIterator::Next()
{
    if (m_current_data && m_pos < m_current_data->size()) {
        m_pos++;
        return;
    }

    m_pos = 0;
    AddressDBIterator* dbit = static_cast<AddressDBIterator*>(m_db_iterator);
    AddressCacheIterator* chit = static_cast<AddressCacheIterator*>(m_cache_iterator);

    if (!*chit || *dbit && dbit->GetKey() <= chit->GetKey()) {
        m_current_key = dbit->GetKey();
        m_current_data = dbit->GetValue();
        dbit->Next();
    } else {
        m_current_key = chit->GetKey();
        m_current_data = chit->GetValue();
        chit->Next();
    }
}

AddressIndexIterator::~AddressIndexIterator()
{
    delete static_cast<AddressDBIterator*>(m_db_iterator);
    delete static_cast<AddressCacheIterator*>(m_cache_iterator);
}

AddressIndexIterator AddressIndex::Iterator(uint64_t key)
{
    AddressIndexIterator it;
    it.m_db_iterator = new AddressDBIterator(m_db->NewIterator(), key);
    {
        lock_guard<recursive_mutex> l(m_mutex);
        it.m_cache_iterator = new AddressCacheIterator(m_accumulated_changes, key);
    }

    it.Next();

    return it;
}
