// SM64COIN: see sm64coin.h.
#include "sm64coin.h"
#include "sm64pow.h"
#include <atomic>
#include <limits>

namespace sm64coin
{
  static std::atomic<bool> s_initialized{false};

  static uint64_t clamp64(const difficulty_type &d)
  {
    if (d > std::numeric_limits<uint64_t>::max())
      return std::numeric_limits<uint64_t>::max();
    return d.convert_to<uint64_t>();
  }

  static std::string last_error()
  {
    char buf[512];
    sm64pow_last_error(buf, sizeof(buf));
    return buf;
  }

  bool init(const std::string &rom_path, std::string &error)
  {
    if (sm64pow_init(rom_path.empty() ? nullptr : rom_path.c_str()) != 1)
    {
      error = last_error();
      return false;
    }
    s_initialized = true;
    return true;
  }

  bool initialized() { return s_initialized; }

  crypto::hash seed_hash(const std::string &hashing_blob)
  {
    crypto::hash h;
    crypto::cn_fast_hash(hashing_blob.data(), hashing_blob.size(), h);
    return h;
  }

  uint32_t seed_from_hashing_blob(const std::string &hashing_blob)
  {
    const crypto::hash h = seed_hash(hashing_blob);
    return sm64pow_seed(reinterpret_cast<const uint8_t *>(h.data));
  }

  uint32_t reseed_frames(const difficulty_type &difficulty) { return sm64pow_reseed_frames(clamp64(difficulty)); }

  crypto::hash proof_id(const std::string &proof)
  {
    crypto::hash h;
    sm64pow_proof_id(reinterpret_cast<const uint8_t *>(proof.data()), proof.size(), reinterpret_cast<uint8_t *>(h.data));
    return h;
  }

  static const uint8_t *u8(const crypto::hash &h) { return reinterpret_cast<const uint8_t *>(h.data); }
  static const uint8_t *u8(const std::string &s) { return reinterpret_cast<const uint8_t *>(s.data()); }

  int64_t verify_block(const crypto::hash &id, const crypto::hash *parent, uint64_t gap, const crypto::hash &seed,
                       const difficulty_type &difficulty, const std::string &proof, std::string &why)
  {
    if (!s_initialized)
    {
      why = "proof-of-play is not initialized (no SM64 ROM loaded)";
      return -1;
    }
    const uint64_t d = difficulty == 0 ? 0 : clamp64(difficulty);
    int64_t r = sm64pow_verify_block(u8(id), parent ? u8(*parent) : nullptr, gap, u8(seed), d, u8(proof), proof.size());
    if (r <= 0)
      why = last_error();
    return r;
  }

  bool has_state(const crypto::hash &id) { return sm64pow_has_state(u8(id)) == 1; }

  bool block_progress(const crypto::hash &id, progress &p)
  {
    int32_t g = 0, e = 0;
    if (!sm64pow_block_progress(u8(id), &p.stars, &p.keys, &g, &e))
      return false;
    p.grand_star = g != 0;
    p.ends_cycle = e != 0;
    return true;
  }

  int proof_start(const std::string &proof) { return sm64pow_proof_start(u8(proof), proof.size()); }

  std::string block_event(const crypto::hash &id)
  {
    char buf[32];
    return sm64pow_block_event(u8(id), buf, sizeof(buf)) ? std::string(buf) : std::string();
  }

  uint64_t stall_seconds() { return sm64pow_stall_seconds(); }

  uint32_t max_frames(const difficulty_type &difficulty, uint64_t elapsed) { return sm64pow_max_frames(clamp64(difficulty), elapsed); }

  uint32_t seed_word(const crypto::hash &seed) { return sm64pow_seed(u8(seed)); }

  int played_block(const crypto::hash &id, const crypto::hash *parent, uint64_t gap, const crypto::hash &seed,
                   const std::string &proof, std::string &out, std::string &why, bool wanted)
  {
    const uint8_t *pp = parent ? u8(*parent) : nullptr;
    auto *fn = wanted ? sm64pow_wanted_block : sm64pow_played_block;
    size_t n = fn(u8(id), pp, gap, u8(seed), u8(proof), proof.size(), nullptr, 0);
    if (n == SIZE_MAX - 1)
      return -2;
    if (n == SIZE_MAX)
    {
      why = last_error();
      return 0;
    }
    out.assign(n, '\0');
    if (fn(u8(id), pp, gap, u8(seed), u8(proof), proof.size(), reinterpret_cast<uint8_t *>(&out[0]), out.size()) != n)
    {
      why = last_error();
      return 0;
    }
    return 1;
  }

  template <typename F>
  static bool size_then_fill(F f, const std::string &in, std::string &out)
  {
    const uint8_t *p = reinterpret_cast<const uint8_t *>(in.data());
    size_t n = f(p, in.size(), nullptr, 0);
    if (n == SIZE_MAX)
      return false;
    out.assign(n, '\0');
    return f(p, in.size(), reinterpret_cast<uint8_t *>(&out[0]), out.size()) == n;
  }

  bool decode_raw(const std::string &proof, std::string &raw) { return size_then_fill(sm64pow_decode_raw, proof, raw); }
  bool reencode(const std::string &proof, std::string &out) { return size_then_fill(sm64pow_reencode, proof, out); }

  uint32_t proof_frames(const std::string &proof)
  {
    return sm64pow_proof_frames(reinterpret_cast<const uint8_t *>(proof.data()), proof.size());
  }

  difficulty_type next_difficulty(const std::vector<uint64_t> &timestamps,
                                  const std::vector<difficulty_type> &cumulative_difficulties)
  {
    const size_t n = std::min(timestamps.size(), cumulative_difficulties.size());
    std::vector<uint64_t> lo(n), hi(n);
    for (size_t i = 0; i < n; ++i)
    {
      lo[i] = (cumulative_difficulties[i] & 0xffffffffffffffffull).convert_to<uint64_t>();
      hi[i] = (cumulative_difficulties[i] >> 64).convert_to<uint64_t>();
    }
    return sm64pow_next_difficulty(timestamps.data(), lo.data(), hi.data(), n);
  }

  difficulty_type effective_difficulty(const difficulty_type &difficulty, uint64_t timestamp, uint64_t parent_timestamp)
  {
    const uint64_t elapsed = timestamp > parent_timestamp ? timestamp - parent_timestamp : 0;
    return sm64pow_effective_difficulty(clamp64(difficulty), elapsed);
  }

  uint64_t target_seconds() { return sm64pow_target_seconds(); }

  task task_for(const difficulty_type &difficulty)
  {
    task t{};
    t.difficulty = clamp64(difficulty);
    sm64pow_params(t.difficulty, &t.max_frames, &t.random_amount, &t.window_length, &t.burst_length);
    sm64pow_probs(t.difficulty, &t.a_prob, &t.b_prob, &t.z_prob);
    return t;
  }

  std::string rules_name()
  {
    char n[128], g[512];
    sm64pow_rules_info(n, sizeof(n), g, sizeof(g));
    return n;
  }

  std::string rules_goal()
  {
    char n[128], g[512];
    sm64pow_rules_info(n, sizeof(n), g, sizeof(g));
    return g;
  }
}
