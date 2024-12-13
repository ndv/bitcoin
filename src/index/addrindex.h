#pragma once

#include <addresstype.h>
#include <chain.h>
#include <compat/byteswap.h>
#include <index/base.h>
#include <util/transaction_identifier.h>

#include <map>
#include <optional>
#include <stdint.h>

static constexpr bool DEFAULT_ADDRINDEX{false};
static constexpr int64_t nMaxAddrIndexCache{2048}; // 2G

struct AddressKey {
    uint64_t key;
    uint8_t bin;

    template<typename Stream>
    void Serialize(Stream& s) const
    {
        s << internal_bswap_64(key);
        if (bin)
            s << bin;
    }

    template<typename Stream>
    void Unserialize(Stream& s)
    {
        s >> key;
        key = internal_bswap_64(key);
        if (s.empty())
            bin = 0;
        else
            s >> bin;
    }
    bool operator<(const AddressKey& other) const
    {
        return key < other.key || (key == other.key && bin < other.bin);
    }
    bool operator==(const AddressKey& other) const
    {
        return key == other.key && bin == other.bin;
    }
    bool operator!=(const AddressKey& other) const
    {
        return !(*this == other);
    }
    bool operator<=(const AddressKey& other) const
    {
        return *this < other || *this == other;
    }
};

struct AddressIndexIterator {
    CDBIterator* m_dbit;
    uint64_t m_key;
    std::vector<Txid> m_tx_ids;
    uint32_t m_pos;
    uint8_t m_nbins;

    AddressIndexIterator(CDBIterator* dbit, uint64_t key, const Txid& tx_from, uint8_t nbins);
    ~AddressIndexIterator();

    operator bool() const;

    uint64_t GetKey();
    Txid& GetValue();

    void Next();
};

/**
 * AddressIndex maintains address -> transactions map.
 */
class AddressIndex final : public BaseIndex
{
public:
    std::optional<AddressKey> GetAddressKey(const CTxDestination& address, uint8_t);

    typedef std::vector<Txid> AddressData;

    std::optional<AddressData> operator[](const AddressKey& key) const;

    explicit AddressIndex(
        std::unique_ptr<interfaces::Chain> chain,
        size_t n_cache_size, bool f_memory = false, bool f_wipe = false);

    AddressIndexIterator Iterator(uint64_t key, const Txid& tx) const;

protected:

    class DB : public BaseIndex::DB
    {
    public:
        explicit DB(size_t n_cache_size, bool f_memory = false, bool f_wipe = false);
    };

    BaseIndex::DB& GetDB() const override;

    [[nodiscard]] bool CustomAppend(const interfaces::BlockInfo& block) override;
    [[nodiscard]] bool CustomRewind(const interfaces::BlockRef& current_tip, const interfaces::BlockRef& new_tip) override;
    bool CustomCommit(CDBBatch& batch) override;

private:
    std::recursive_mutex m_mutex;
    std::string m_name;
    std::unique_ptr<AddressIndex::DB> m_db;
    std::map<AddressKey, AddressData> m_accumulated_changes;
    int m_height;

    bool AllowPrune() const override { return true; }

    void addScriptToAccumulatedChanges(const CScript& script, const CTransactionRef& tx, uint8_t);

    void popScriptFromAccumulatedChanges(const CScript& script, const CTransactionRef& tx, uint8_t);

    void RewindBlock(const CBlock& block, const CBlockIndex* block_index);

    std::optional<AddressData> Read(const AddressKey& key) const;

    int GetNBins() const;
};

extern std::unique_ptr<AddressIndex> g_address_index;
