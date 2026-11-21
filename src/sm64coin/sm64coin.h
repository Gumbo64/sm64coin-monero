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

  // The perturbation seed, from cn_fast_hash(block hashing blob).
  uint32_t seed_from_hashing_blob(const std::string &hashing_blob);

  // What the block id commits to for a proof blob (independent of its codec).
  crypto::hash proof_id(const std::string &proof);

  // Replays `proof`. Returns the number of frames when valid, 0 otherwise.
  uint64_t verify(uint32_t seed, const difficulty_type &difficulty, const std::string &proof, std::string &why);

  // Rules hooks (see pow/sm64pow/src/rules.rs).
  difficulty_type next_difficulty(const std::vector<uint64_t> &timestamps,
                                  const std::vector<difficulty_type> &cumulative_difficulties);
  difficulty_type effective_difficulty(const difficulty_type &difficulty, uint64_t timestamp, uint64_t parent_timestamp);
  uint64_t target_seconds();

  // Proof blob -> raw pads (4 bytes per frame). False if it doesn't decode.
  bool decode_raw(const std::string &proof, std::string &raw);
  // Re-encodes with the smallest codec; the block id is unchanged.
  bool reencode(const std::string &proof, std::string &out);

  struct task
  {
    uint64_t difficulty;
    uint32_t max_frames;
    uint32_t random_amount;
    uint32_t window_length;
    uint32_t burst_length;
    float a_prob, b_prob, z_prob;
  };
  task task_for(const difficulty_type &difficulty);
  std::string rules_name();
  std::string rules_goal();
}
