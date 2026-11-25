// SM64COIN: the daemon's whole interface to proof-of-play.
//
// Monero's hash-based PoW is replaced by replaying a Super Mario 64 run. The
// rules (success condition, difficulty -> task, retargeting, decay) and the
// proof format (codecs, compression) live in the Rust crate pow/sm64pow; this
// file only adapts types. Call sites in upstream code are one-liners marked
// "SM64COIN" so upstream merges stay easy.
#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <boost/multiprecision/cpp_int.hpp>
#include "crypto/hash.h"

namespace sm64coin
{
  typedef boost::multiprecision::uint128_t difficulty_type;

  // Loads the ROM (path empty: $SM64COIN_ROM, ./baserom.us.z64, ~/.sm64coin/baserom.us.z64).
  bool init(const std::string &rom_path, std::string &error);
  bool initialized();

  // The perturbation seed: cn_fast_hash of a block hashing blob, all 256 bits
  // (the caller passes the blob with the timestamp zeroed: see
  // Blockchain::sm64_seed); and its first word, for display.
  crypto::hash seed_hash(const std::string &hashing_blob);
  uint32_t seed_from_hashing_blob(const std::string &hashing_blob);
  uint32_t reseed_frames(const difficulty_type &difficulty);

  // What the block id commits to for a proof blob (independent of its codec).
  crypto::hash proof_id(const std::string &proof);

  // Blocks continue the game from their parent's end state (pow/sm64pow/src/chain.rs).
  // Verifies block `id` on top of `parent` (nullptr: the genesis block),
  // timestamped `gap` seconds after it, at effective `difficulty` (0: rebuild
  // an accepted block's end state, no time limit). Returns frames (>0) when
  // valid, 0 invalid, -2 when the parent's end state isn't cached (rebuild the
  // parent first), -1 internal error. Caches the end state when valid.
  int64_t verify_block(const crypto::hash &id, const crypto::hash *parent, uint64_t gap, const crypto::hash &seed,
                       const difficulty_type &difficulty, const std::string &proof, std::string &why);
  bool has_state(const crypto::hash &id);
  // Block `id`'s cached end state (the game's save state), gzip; false unless cached.
  bool end_state_gz(const crypto::hash &id, std::string &out);

  // The last few blocks' end states on disk in `dir` (loaded now): a restart
  // needs no replay of the cycle. Returns how many were loaded, -1 on error.
  int set_state_dir(const std::string &dir);

  // The parallel pre-pass of a sync batch, in chain order (chain::preverify):
  // replays the batch's proofs chain by chain on `threads` threads, so the
  // sequential check finds each run. Validity is still decided there.
  struct preverify_block { crypto::hash id; crypto::hash parent; bool genesis_parent; crypto::hash seed; const std::string *proof; };
  uint64_t preverify(const std::vector<preverify_block> &batch, unsigned threads);
  struct progress { uint32_t stars = 0, keys = 0; bool grand_star = false, ends_cycle = false; };
  // A cached block's end progress. False if not cached.
  bool block_progress(const crypto::hash &id, progress &p);
  // What a cached block's run added ("c09s1", "key1", "grand"; empty if unknown). Bookkeeping.
  std::string block_event(const crypto::hash &id);
  // A proof's start: 0 from the parent's end state, 1 from power-on, -1 bad.
  int proof_start(const std::string &proof);
  // How many seconds earlier a power-on restart on top of a parent with this
  // progress takes its limit (valid only that long after the parent); -1: not allowed.
  int64_t restart_delay(const progress &parent);
  // Fork choice by the number of blocks instead of cumulative difficulty.
  bool weigh_by_blocks();
  // The hold policy: 0 to process a block extending the tip now, else the unix second to hold it until.
  uint64_t hold_until(const difficulty_type &difficulty, uint64_t parent_ts, uint64_t block_ts, uint64_t now, uint32_t frames, uint64_t restart_delay);
  // No block but the genesis block may be timestamped before this.
  uint64_t launch_timestamp();
  // The time limit of a block at retarget `difficulty`, `elapsed` seconds after its parent.
  uint32_t max_frames(const difficulty_type &difficulty, uint64_t elapsed);
  // The first word of a seed hash (display only).
  uint32_t seed_word(const crypto::hash &seed);
  // Every frame's played pad (4 bytes each) of block `id`'s run. 1 ok, 0
  // error, -2 parent state not cached. Parent arguments as for verify_block.
  int played_block(const crypto::hash &id, const crypto::hash *parent, uint64_t gap, const crypto::hash &seed,
                   const std::string &proof, std::string &out, std::string &why, bool wanted = false); // SM64COIN: wanted = the proof's inputs, not every played pad

  // Rules hooks (see pow/sm64pow/src/rules.rs).
  difficulty_type next_difficulty(const std::vector<uint64_t> &timestamps,
                                  const std::vector<difficulty_type> &cumulative_difficulties);
  difficulty_type effective_difficulty(const difficulty_type &difficulty, uint64_t timestamp, uint64_t parent_timestamp);
  uint64_t target_seconds();

  // Proof blob -> raw pads (4 bytes per frame). False if it doesn't decode.
  bool decode_raw(const std::string &proof, std::string &raw);
  // Re-encodes with the smallest codec; the block id is unchanged.
  bool reencode(const std::string &proof, std::string &out);
  // Frames the proof's run lasted (0 if it doesn't decode).
  uint32_t proof_frames(const std::string &proof);

  // Admission policy (pow/sm64pow/src/admit.rs, docs/DOS.md): which blocks
  // earn a replay. Relay policy, not consensus.
  // Where the blocks handled on this thread come from, while in scope.
  enum source_kind { source_relay = 1, source_sync = 2, source_rpc_submit = 3 };
  class source_scope
  {
  public:
    // `top`: for source_sync, the height of the span's last block.
    source_scope(const std::string &host, source_kind kind, uint64_t top = 0);
    ~source_scope();
    source_scope(const source_scope &) = delete;
    source_scope &operator=(const source_scope &) = delete;
  private:
    void *m_handle;
  };
  // Whether to replay an alternative block at `height` (our tip at `top`);
  // main_seed: the seed of our main-chain block at that height, if any. False: skip it, `why` says why.
  bool admit_alt(const crypto::hash &id, const crypto::hash &parent, const crypto::hash &seed, uint32_t frames,
                 uint64_t height, uint64_t top, const crypto::hash *main_seed, std::string &why);
  // Whether to replay a block extending the tip, claiming `frames` (charged to this thread's source).
  bool admit_relay(uint32_t frames, std::string &why);
  // Whether a restricted-RPC client may submit a block now.
  bool rpc_submit_allowed(const std::string &host);
  // An RPC call that may replay, while in scope: its replays draw on the RPC replay budget.
  class rpc_scope
  {
  public:
    rpc_scope();
    ~rpc_scope();
    rpc_scope(const rpc_scope &) = delete;
    rpc_scope &operator=(const rpc_scope &) = delete;
  private:
    void *m_handle;
  };

  struct task
  {
    uint64_t difficulty;
    uint32_t max_frames;
    uint32_t random_amount;
    uint32_t window_length;
    uint32_t burst_length;
    float a_prob, b_prob, z_prob;
    uint32_t timing_mix, pad_mix; // simulated frames between state mixes into the poke streams (0: never)
  };
  task task_for(const difficulty_type &difficulty);
  std::string rules_name();
  std::string rules_goal();
}
