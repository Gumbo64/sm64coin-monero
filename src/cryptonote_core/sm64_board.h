// SM64COIN: the mining leaderboard, kept by every node and shared over p2p
// (NOTIFY_SM64_BOARD). Each node keeps the top 50 addresses by blocks mined,
// counted by its own scan of the chain with each entry's view key, so nodes
// with the same chain agree on the board, and spam can't grow it: an entry
// that mined nothing, or doesn't make the top 50, is neither stored nor
// relayed. Names are signed with the address's spend key over
// "sm64coin-board:<timestamp>:<name>"; the latest timestamp wins (a rename).
// Leaving the board is not supported.
#pragma once

#include <mutex>
#include <string>
#include <vector>

#include "cryptonote_basic/cryptonote_basic.h"
#include "cryptonote_protocol/cryptonote_protocol_defs.h"
#include "crypto/crypto.h"

namespace cryptonote
{
  class Blockchain;

  struct sm64_board_row
  {
    sm64_board_entry entry;
    uint64_t blocks = 0;
    uint64_t reward = 0;
    uint64_t last_height = 0;
  };

  class sm64_board
  {
  public:
    static constexpr size_t TOP_N = 50;

    void init(const std::string &path, network_type nettype);
    // Admits the entries that verify, have mined blocks and make the top 50
    // (or rename an entry with a later signed timestamp). Returns those that
    // changed the board, to relay. `why` gets the reason of the last refusal.
    std::vector<sm64_board_entry> offer(const std::vector<sm64_board_entry> &in, Blockchain &bc, std::string *why = nullptr);
    // Counts the blocks added since the last call (all of them after a reorg).
    void update(Blockchain &bc);
    std::vector<sm64_board_row> rows() const;
    std::vector<sm64_board_entry> entries() const;

  private:
    struct item
    {
      sm64_board_row row;
      account_public_address addr;
      crypto::secret_key view;
    };
    bool check(const sm64_board_entry &e, item &out, std::string &why) const;
    void count(item &it, Blockchain &bc, uint64_t from, uint64_t to) const;
    void rank();
    void save() const;

    mutable std::mutex m_lock;
    std::vector<item> m_items;
    uint64_t m_scanned = 0;
    crypto::hash m_top = crypto::null_hash;
    std::string m_path;
    network_type m_nettype = MAINNET;
    std::vector<uint64_t> m_scans; // times of recent full scans (rate limit)
  };
}
