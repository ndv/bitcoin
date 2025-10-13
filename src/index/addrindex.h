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
        s << internal_bswap_64(key) << bin;
    }

    template<typename Stream>
    void Unserialize(Stream& s)
    {
        s >> key >> bin;
        key = internal_bswap_64(key);
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
    operator bool() const;
    uint64_t GetKey();
    Txid& GetValue();
    void Next();
    ~AddressIndexIterator();

    void* m_db_iterator;
    void* m_cache_iterator;
    AddressKey m_current_key;
    std::vector<Txid> m_current_data;
    uint32_t m_pos = 0;
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

    AddressIndexIterator Iterator(uint64_t key);

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
