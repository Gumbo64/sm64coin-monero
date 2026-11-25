// SM64COIN: the mining leaderboard, kept by every node and shared over p2p
// (NOTIFY_SM64_BOARD). Each node keeps the top 50 addresses by blocks mined.
// An entry carries its own evidence: the heights of the blocks the address
// mined. The node checks each claimed height with ONE key derivation against
// that block's coinbase (random order, the whole entry is refused at the first
// lie), time-sliced in the background; the count is the verified heights, so
// nodes with the same chain agree, spam can't grow the board (an entry that
// can't make the top 50 is not even verified), and the chain is never
// scanned: new blocks are checked against the <= 50 board view keys only
// (and a reorg forgets the hits at and above its fork). Names are signed with
// the address's spend key over "sm64coin-board:<timestamp>:<name>"; the latest
// timestamp wins (a rename, at most one per address per 10 minutes). Leaving
// the board is not supported.
//
// Everything an outsider can ask for is rate limited per source (p2p
// connection; the RPC as a whole, which every web client shares), entries
// already judged are dropped before any crypto, the file is written at most
// once a minute, and the whole board can be switched off (--sm64-no-leaderboard,
// or at run time) so an operator can stop it without a restart.
#pragma once

#include <atomic>
#include <deque>
#include <map>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

#include "cryptonote_basic/cryptonote_basic.h"
#include "cryptonote_protocol/cryptonote_protocol_defs.h"
#include "crypto/crypto.h"
#include "crypto/hash.h"

namespace cryptonote
{
  class Blockchain;

  struct sm64_board_row
  {
    sm64_board_entry entry; // without heights
    uint64_t blocks = 0;
    uint64_t reward = 0;
    uint64_t last_height = 0;
  };

  // What offer() tells its caller besides the entries that changed the board.
  struct sm64_board_result
  {
    std::vector<sm64_board_entry> changed; // renamed on the board now: relay these
    bool queued = false;   // accepted; it joins when its heights are verified (relayed then)
    bool abuse = false;    // the source keeps sending invalid entries or flooding: drop it
    bool disabled = false; // the board is turned off on this node
    std::string why;       // the reason of the last refusal
  };

  class sm64_board
  {
  public:
    static constexpr size_t TOP_N = 50;
    static constexpr size_t MAX_HEIGHTS = 20000;     // claimed by one entry
    static constexpr uint64_t HISTORY = 64;          // reorg depth handled by forgetting hits
    static constexpr uint64_t RENAME_SECONDS = 600;  // per address
    static constexpr uint64_t SAVE_SECONDS = 60;
    static constexpr size_t PENDING_MAX = 64, PENDING_PER_SOURCE = 6, PENDING_HEIGHTS = 200000;
    static constexpr uint64_t MAX_CATCH_UP = 2000;   // blocks checked after a pause (else re-verified)

    void init(const std::string &path, network_type nettype);
    // `source`: who sent it ("p:<connection id>", or "rpc" for the restricted
    // RPC that every web client shares). Renames are applied at once; a new
    // address is queued (its claimed heights are verified by update()).
    sm64_board_result offer(const std::vector<sm64_board_entry> &in, Blockchain &bc, const std::string &source);
    // Called (cheaply) when a block was added at `height` (and so the chain
    // above it replaced, after a reorg): wakes update().
    void block_added(uint64_t height);
    // Time-sliced background work: checks the blocks added since last time
    // against the board's view keys, verifies queued claims, writes the file
    // if due. Returns the entries that joined the board, to relay.
    std::vector<sm64_board_entry> update(Blockchain &bc);
    void flush(); // writes the file now if it changed (shutdown)
    std::vector<sm64_board_row> rows() const;
    std::vector<sm64_board_entry> entries() const; // with their verified heights
    void set_enabled(bool on);
    bool enabled() const { return m_enabled; }
    uint64_t derivations() const { return m_derivations; } // block reads + derivations so far

  private:
    struct hit { uint64_t height; uint64_t reward; };
    struct item
    {
      sm64_board_row row;
      account_public_address addr;
      crypto::secret_key view;
      std::vector<hit> hits;        // verified, ascending by height
      std::vector<uint64_t> claims; // still to verify (random order)
      bool lenient = false;         // a claim that fails is dropped (re-verification), not a lie
      uint64_t changed_at = 0;      // time of the last rename, or of queueing (not saved)
      std::string source;           // pending: who sent it
    };
    struct bucket
    {
      double tokens = -1;
      uint64_t at_ms = 0;
    };
    struct source_state
    {
      bucket msgs, entries;
      double strikes = 0;
      uint64_t strikes_at = 0, seen = 0;
    };

    // `invalid`: the entry is malformed or forged (not merely too new)
    bool check(const sm64_board_entry &e, item &out, std::string &why, bool &invalid) const;
    bool cheap_check(const sm64_board_entry &e, std::string &why, bool &invalid) const;
    // does block `h` pay the address? (one block read, one derivation per output set)
    bool block_pays(const item &it, Blockchain &bc, uint64_t h, uint64_t &reward) const;
    static void add_hit(item &it, uint64_t h, uint64_t reward);
    static void drop_from(item &it, uint64_t height);
    static void refresh(item &it);
    void rank();
    void save(bool force);
    static bool take(bucket &b, double cap, double per_sec, double n, uint64_t now_ms);
    source_state &source_of(const std::string &s, uint64_t now_ms);
    void strike(source_state &s, double n, uint64_t now_ms);
    void forget_after(uint64_t fork);

    mutable std::mutex m_lock;      // the data below; never held across block reads
    std::mutex m_scan_lock;         // one update() at a time; guards m_next, m_ids
    std::vector<item> m_items;      // the board
    std::vector<item> m_pending;    // verified signature, claims being verified
    uint64_t m_next = 0;            // blocks below this are checked
    bool m_have_next = false;
    std::deque<crypto::hash> m_ids; // ids of the last HISTORY blocks below m_next
    uint64_t m_saved_tip = 0;       // from the file, until init is settled
    crypto::hash m_saved_tip_id = crypto::null_hash;
    std::string m_path;
    network_type m_nettype = MAINNET;
    bool m_dirty = false;
    uint64_t m_saved_at = 0;
    std::map<std::string, source_state> m_sources;
    bucket m_p2p_verify; // all peers together
    std::unordered_map<crypto::hash, uint64_t> m_seen; // entry hash -> expiry (p2p only)
    std::atomic<bool> m_enabled{true};
    std::atomic<bool> m_wake{true};
    std::atomic<bool> m_work{false}; // claims are waiting to be verified
    std::atomic<uint64_t> m_rewind{UINT64_MAX};
    mutable std::atomic<uint64_t> m_derivations{0};
    uint64_t m_poll_at = 0;
  };
}
