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

  static const uint8_t *sig8(const crypto::signature &s) { return reinterpret_cast<const uint8_t *>(&s); }

  int64_t verify_signed_block(const crypto::hash &id, const crypto::hash *parent, uint64_t gap, const crypto::hash &seed,
                              const difficulty_type &difficulty, const std::string &proof, const std::string &nonce,
                              const crypto::signature &sig, std::string &why)
  {
    if (!s_initialized)
    {
      why = "proof-of-play is not initialized (no SM64 ROM loaded)";
      return -1;
    }
    const uint64_t d = difficulty == 0 ? 0 : clamp64(difficulty);
    int64_t r = sm64pow_verify_signed_block(u8(id), parent ? u8(*parent) : nullptr, gap, u8(seed), d, u8(proof), proof.size(),
                                            u8(nonce), nonce.size(), sig8(sig));
    if (r <= 0)
      why = last_error();
    return r;
  }

  bool check_signature(const crypto::hash &seed, const std::string &proof, const std::string &nonce, const crypto::signature &sig, std::string &why)
  {
    if (sm64pow_check_signature(u8(seed), u8(proof), proof.size(), u8(nonce), nonce.size(), sig8(sig)) == 1)
      return true;
    why = last_error();
    return false;
  }

  sibling judge_sibling(const crypto::hash &seed, const std::string &nonce, const std::string &main_proof, const crypto::signature &main_sig,
                        const std::string &alt_proof, const crypto::signature &alt_sig, std::string &evidence)
  {
    std::string out(512, '\0');
    const int32_t r = sm64pow_judge_sibling(u8(seed), u8(nonce), nonce.size(), u8(main_proof), main_proof.size(), sig8(main_sig),
                                            u8(alt_proof), alt_proof.size(), sig8(alt_sig), reinterpret_cast<uint8_t *>(&out[0]), out.size());
    if (r == sibling_equivocation || r == sibling_known_evidence)
      evidence = out.substr(0, 272);
    return static_cast<sibling>(r);
  }

  int note_claim(const crypto::hash &seed, const std::string &proof, const std::string &nonce, const crypto::signature &sig, std::string &why)
  {
    const int r = sm64pow_note_claim(u8(seed), u8(proof), proof.size(), u8(nonce), nonce.size(), sig8(sig));
    if (r <= 0)
      why = last_error();
    return r < 0 ? 0 : r;
  }

  static queue_facts_cb g_facts_cb = nullptr;
  static int32_t facts_trampoline(const uint8_t *parent, uint8_t *child_id, uint32_t *child_frames)
  {
    crypto::hash p, c;
    memcpy(p.data, parent, 32);
    c = crypto::null_hash;
    const int r = g_facts_cb(p, c, *child_frames);
    memcpy(child_id, c.data, 32);
    return r;
  }
  void queue_start(queue_facts_cb cb, unsigned threads)
  {
    g_facts_cb = cb;
    sm64pow_queue_set_threads(threads);
    sm64pow_queue_set_facts(&facts_trampoline);
  }
  int queue_submit(const queue_job &j, std::string &why)
  {
    const int r = sm64pow_queue_submit(u8(j.id), u8(j.parent), j.genesis_parent, j.gap, u8(j.seed), j.difficulty, u8(*j.proof), j.proof->size(), j.frames, j.stamp, j.due, j.sig ? sig8(*j.sig) : nullptr);
    if (r >= 2)
      why = last_error();
    return r;
  }
  int queue_replay_now(const queue_job &j, std::string &why)
  {
    const int r = sm64pow_queue_replay_now(u8(j.id), u8(j.parent), j.genesis_parent, j.gap, u8(j.seed), j.difficulty, u8(*j.proof), j.proof->size(), j.frames, j.stamp, j.sig ? sig8(*j.sig) : nullptr);
    if (r == 0 || r == 2)
      why = last_error();
    return r;
  }
  int queue_wait(unsigned timeout_ms, crypto::hash &id, std::string &why)
  {
    const int r = sm64pow_queue_wait(timeout_ms, reinterpret_cast<uint8_t *>(id.data));
    if (r == 0 || r == 2)
      why = last_error();
    return r;
  }
  bool queue_take_cleared(const crypto::hash &id) { return sm64pow_queue_take_cleared(u8(id)) == 1; }
  void queue_also(const crypto::hash &id) { sm64pow_queue_also(u8(id)); }

  int evidence_received(const std::string &evidence, const std::string &host, uint64_t top)
  {
    return sm64pow_evidence_received(u8(evidence), evidence.size(), host.c_str(), top);
  }
  size_t evidence_max() { return sm64pow_evidence_max(); }
  bool evidence_for(const crypto::hash &seed, std::string &evidence)
  {
    evidence.assign(sm64pow_evidence_max(), '\0');
    const size_t n = sm64pow_evidence_for(u8(seed), reinterpret_cast<uint8_t *>(&evidence[0]), evidence.size());
    evidence.resize(n <= evidence.size() ? n : 0);
    return !evidence.empty();
  }
  void evidence_recent(uint64_t top, std::vector<std::string> &out)
  {
    std::string e(sm64pow_evidence_max(), '\0');
    for (size_t i = 0; i < 64; ++i)
    {
      const size_t n = sm64pow_evidence_recent(top, i, reinterpret_cast<uint8_t *>(&e[0]), e.size());
      if (n == 0 || n > e.size())
        break;
      out.push_back(e.substr(0, n));
    }
  }
  void evidence_persist(const std::string &path) { sm64pow_evidence_persist(path.c_str()); }
  bool fork_choice(uint64_t main_len, const std::vector<crypto::hash> &main_seeds, uint64_t alt_len, const std::vector<crypto::hash> &alt_seeds)
  {
    std::string m, a;
    for (const auto &h : main_seeds) m.append(h.data, 32);
    for (const auto &h : alt_seeds) a.append(h.data, 32);
    return sm64pow_fork_choice(main_len, u8(m), main_seeds.size(), alt_len, u8(a), alt_seeds.size()) == 1;
  }
  void note_history(const crypto::hash &id, const crypto::hash &parent, const crypto::hash &seed, uint32_t frames, uint64_t timestamp, const crypto::signature &sig, const std::string &proof)
  {
    sm64pow_note_history(u8(id), u8(parent), u8(seed), frames, timestamp, sig8(sig), u8(proof), proof.size());
  }
  block_scope::block_scope(const std::string &blob, const crypto::hash &seed, uint64_t height, uint64_t top) : m_handle(sm64pow_block_scope_enter(u8(blob), blob.size(), u8(seed), height, top)) {}
  void set_max_reorg(uint64_t n) { sm64pow_set_max_reorg(n); }
  void allow_reorg(const crypto::hash &id) { sm64pow_allow_reorg(u8(id)); }
  bool reorg_allowed(uint64_t depth, const std::vector<crypto::hash> &alt_ids)
  {
    std::string s;
    for (const auto &h : alt_ids) s.append(h.data, 32);
    return sm64pow_reorg_allowed(depth, u8(s), alt_ids.size()) == 1;
  }
  bool rpc_bulk_ok() { return sm64pow_rpc_bulk_ok() == 1; }
  void rpc_bulk_charge(uint64_t bytes) { sm64pow_rpc_bulk_charge(bytes); }
  block_scope::~block_scope() { sm64pow_block_scope_leave(m_handle); }

  bool take_evidence(std::string &evidence)
  {
    evidence.assign(sm64pow_evidence_max(), '\0');
    const size_t n = sm64pow_take_evidence(reinterpret_cast<uint8_t *>(&evidence[0]), evidence.size());
    evidence.resize(n <= evidence.size() ? n : 0);
    return !evidence.empty();
  }

  void note_eligible(const crypto::hash &id, const crypto::hash &parent, const crypto::hash &seed, uint32_t frames, uint64_t timestamp, const crypto::signature &sig, const std::string &proof)
  {
    sm64pow_note_eligible(u8(id), u8(parent), u8(seed), frames, timestamp, sig8(sig), u8(proof), proof.size());
  }
  bool displaces(const crypto::hash &tip, const crypto::hash &alt) { return sm64pow_displaces(u8(tip), u8(alt)) == 1; }
  bool pof_candidate(const crypto::hash &tip, const crypto::hash &id, const crypto::hash &seed, uint32_t frames, uint64_t timestamp, const crypto::signature &sig, const std::string &proof) { return sm64pow_pof_candidate(u8(tip), u8(id), u8(seed), frames, timestamp, sig8(sig), u8(proof), proof.size()) == 1; }
  bool stale(uint64_t timestamp) { return sm64pow_stale(timestamp) == 1; }
  bool stale_block(const crypto::hash &id, uint64_t timestamp) { return sm64pow_stale_block(u8(id), timestamp) == 1; }
  bool restamp_preferred(const crypto::hash &tip, const crypto::hash &seed, uint64_t timestamp, const crypto::hash &id)
  {
    return sm64pow_restamp_preferred(u8(tip), u8(seed), timestamp, u8(id)) == 1;
  }
  uint64_t rpc_submit_ahead() { return sm64pow_rpc_submit_ahead(); }

  int64_t choose_parent(const crypto::hash &tip_seed, const std::vector<crypto::hash> &sibling_seeds)
  {
    std::string s;
    for (const auto &h : sibling_seeds)
      s.append(h.data, 32);
    return sm64pow_choose_parent(u8(tip_seed), u8(s), sibling_seeds.size());
  }

  bool has_state(const crypto::hash &id) { return sm64pow_has_state(u8(id)) == 1; }

  bool end_state_gz(const crypto::hash &id, std::string &out)
  {
    size_t n = sm64pow_end_state_gz(u8(id), nullptr, 0);
    if (n == SIZE_MAX)
      return false;
    out.assign(n, '\0');
    return sm64pow_end_state_gz(u8(id), reinterpret_cast<uint8_t *>(&out[0]), out.size()) == n;
  }

  int set_state_dir(const std::string &dir) { return sm64pow_set_state_dir(dir.c_str()); }

  uint64_t preverify(const std::vector<preverify_block> &batch, unsigned threads)
  {
    if (!s_initialized || batch.empty())
      return 0;
    const size_t n = batch.size();
    std::vector<uint8_t> ids(32 * n), parents(32 * n, 0), seeds(32 * n);
    std::vector<uint64_t> offsets(n + 1, 0), gaps(n, UINT64_MAX);
    std::string blobs;
    for (size_t i = 0; i < n; ++i)
    {
      memcpy(&ids[32 * i], &batch[i].id, 32);
      if (!batch[i].genesis_parent)
        memcpy(&parents[32 * i], &batch[i].parent, 32);
      memcpy(&seeds[32 * i], &batch[i].seed, 32);
      blobs += *batch[i].proof;
      gaps[i] = batch[i].gap;
      offsets[i + 1] = blobs.size();
    }
    return sm64pow_preverify(n, ids.data(), parents.data(), seeds.data(), u8(blobs), offsets.data(), gaps.data(), threads);
  }

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

  bool weigh_by_blocks() { return sm64pow_weigh_by_blocks(); }
  uint64_t hold_until(const difficulty_type &difficulty, uint64_t parent_ts, uint64_t block_ts, uint64_t now, uint32_t frames, uint64_t restart_delay)
  {
    return sm64pow_hold_until(clamp64(difficulty), parent_ts, block_ts, now, frames, restart_delay);
  }
  uint64_t launch_timestamp() { return sm64pow_launch_timestamp(); }
  int64_t restart_delay(const progress &parent) { return sm64pow_restart_delay(parent.stars, parent.keys, parent.grand_star); }

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

  source_scope::source_scope(const std::string &host, source_kind kind, uint64_t top)
    : m_handle(sm64pow_source_enter(host.c_str(), (int32_t)kind, top))
  {
  }
  source_scope::~source_scope()
  {
    sm64pow_source_leave(m_handle);
  }
  bool admit_alt(const crypto::hash &id, const crypto::hash &parent, const crypto::hash &seed, uint32_t frames,
                 uint64_t height, uint64_t top, const crypto::hash *main_seed, std::string &why)
  {
    const auto p = [](const crypto::hash &h) { return reinterpret_cast<const uint8_t *>(h.data); };
    if (sm64pow_admit_alt(p(id), p(parent), p(seed), frames, height, top, main_seed ? p(*main_seed) : nullptr))
      return true;
    why = last_error();
    return false;
  }
  source_kind current_source() { return static_cast<source_kind>(sm64pow_source_kind()); }

  bool admit_relay(uint32_t frames, std::string &why)
  {
    if (sm64pow_admit_relay(frames))
      return true;
    why = last_error();
    return false;
  }
  bool rpc_submit_allowed(const std::string &host)
  {
    return sm64pow_rpc_submit_allowed(host.c_str()) != 0;
  }
  rpc_scope::rpc_scope() : m_handle(sm64pow_rpc_enter())
  {
  }
  rpc_scope::~rpc_scope()
  {
    sm64pow_rpc_leave(m_handle);
  }

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
    sm64pow_mix(t.difficulty, &t.timing_mix, &t.pad_mix);
    return t;
  }

  std::string rules_name()
  {
    char n[128], g[512];
    sm64pow_rules_info(n, sizeof(n), g, sizeof(g));
    return n;
  }

  std::string release_version()
  {
#ifdef SM64COIN_VERSION
    return SM64COIN_VERSION;
#else
    return "dev";
#endif
  }

  std::string game_build()
  {
    char b[128];
    sm64pow_game_build(b, sizeof(b));
    return b;
  }

  std::string rules_goal()
  {
    char n[128], g[512];
    sm64pow_rules_info(n, sizeof(n), g, sizeof(g));
    return g;
  }
}
