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

  uint32_t seed_from_hashing_blob(const std::string &hashing_blob)
  {
    crypto::hash h;
    crypto::cn_fast_hash(hashing_blob.data(), hashing_blob.size(), h);
    return sm64pow_seed(reinterpret_cast<const uint8_t *>(h.data));
  }

  crypto::hash proof_id(const std::string &proof)
  {
    crypto::hash h;
    sm64pow_proof_id(reinterpret_cast<const uint8_t *>(proof.data()), proof.size(), reinterpret_cast<uint8_t *>(h.data));
    return h;
  }

  uint64_t verify(uint32_t seed, const difficulty_type &difficulty, const std::string &proof, std::string &why)
  {
    if (!s_initialized)
    {
      why = "proof-of-play is not initialized (no SM64 ROM loaded)";
      return 0;
    }
    int64_t r = sm64pow_verify(seed, clamp64(difficulty), reinterpret_cast<const uint8_t *>(proof.data()), proof.size());
    if (r <= 0)
    {
      why = last_error();
      return 0;
    }
    return static_cast<uint64_t>(r);
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
