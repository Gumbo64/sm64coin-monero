// SM64COIN: see sm64_board.h.
#include "sm64_board.h"

#include <algorithm>
#include <chrono>
#include <ctime>
#include <random>

#include "blockchain.h"
#include "common/base58.h"
#include "common/varint.h"
#include "crypto/hash.h"
#include "cryptonote_basic/cryptonote_basic_impl.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_config.h"
#include "string_tools.h"
#include "storages/portable_storage_template_helper.h"

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "sm64.board"

namespace cryptonote
{
  namespace
  {
    struct file_item
    {
      sm64_board_entry entry; // with its verified heights
      std::vector<uint64_t> rewards; // one per height
      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(entry)
        KV_SERIALIZE(rewards)
      END_KV_SERIALIZE_MAP()
    };
    struct board_file
    {
      std::vector<file_item> items;
      uint64_t tip = 0; // blocks below this were checked
      std::string tip_id; // id of block tip - 1
      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(items)
        KV_SERIALIZE(tip)
        KV_SERIALIZE(tip_id)
      END_KV_SERIALIZE_MAP()
    };

    uint64_t now_ms()
    {
      return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch()).count();
    }

    constexpr uint64_t FUTURE_SECONDS = 30 * 60; // a signed timestamp may be this far ahead of our clock
    constexpr uint64_t SLICE_MS = 300;           // background work per update()
    constexpr uint64_t SEEN_SECONDS = 600;
    constexpr size_t SEEN_MAX = 8192;
    constexpr size_t MAX_MESSAGE_HEIGHTS = 200000;

    // What the owner signs: wallet2::sign's message, spend-key mode.
    std::string signed_text(const sm64_board_entry &e)
    {
      return "sm64coin-board:" + std::to_string(e.timestamp) + ":" + e.name;
    }

    // wallet2's get_message_hash (SigV2).
    crypto::hash message_hash(const std::string &data, const account_public_address &a, uint8_t mode)
    {
      KECCAK_CTX ctx;
      keccak_init(&ctx);
      keccak_update(&ctx, (const uint8_t *)config::HASH_KEY_MESSAGE_SIGNING, sizeof(config::HASH_KEY_MESSAGE_SIGNING));
      keccak_update(&ctx, (const uint8_t *)&a.m_spend_public_key, sizeof(crypto::public_key));
      keccak_update(&ctx, (const uint8_t *)&a.m_view_public_key, sizeof(crypto::public_key));
      keccak_update(&ctx, &mode, 1);
      char len_buf[(sizeof(size_t) * 8 + 6) / 7];
      char *ptr = len_buf;
      tools::write_varint(ptr, data.size());
      keccak_update(&ctx, (const uint8_t *)len_buf, ptr - len_buf);
      keccak_update(&ctx, (const uint8_t *)data.data(), data.size());
      crypto::hash h;
      keccak_finish(&ctx, (uint8_t *)&h);
      return h;
    }

    // A SigV2 signature with the spend key (wallet2::verify, mode 0 only).
    bool signed_by_spend_key(const std::string &data, const account_public_address &a, const std::string &sig)
    {
      if (sig.size() < 5 || sig.compare(0, 5, "SigV2") != 0)
        return false;
      std::string decoded;
      crypto::signature s;
      if (!tools::base58::decode(sig.substr(5), decoded) || decoded.size() != sizeof(s))
        return false;
      memcpy(&s, decoded.data(), sizeof(s));
      return crypto::check_signature(message_hash(data, a, 0), a.m_spend_public_key, s);
    }

    bool better(const sm64_board_row &x, const sm64_board_row &y)
    {
      if (x.blocks != y.blocks) return x.blocks > y.blocks;
      if (x.reward != y.reward) return x.reward > y.reward;
      return x.entry.address < y.entry.address;
    }

    crypto::hash entry_hash(const sm64_board_entry &e)
    {
      std::string s = e.address + '\n' + e.name + '\n' + e.view_key + '\n' + std::to_string(e.timestamp) + '\n' + e.signature + '\n';
      s.append((const char *)e.heights.data(), e.heights.size() * sizeof(uint64_t));
      crypto::hash h;
      crypto::cn_fast_hash(s.data(), s.size(), h);
      return h;
    }

    // The coinbase outputs of a block that pay `addr` (view key `view`).
    bool pays(const block &b, const account_public_address &addr, const crypto::secret_key &view, uint64_t &reward)
    {
      const crypto::public_key r = get_tx_pub_key_from_extra(b.miner_tx);
      crypto::key_derivation d;
      if (r == crypto::null_pkey || !crypto::generate_key_derivation(r, view, d))
        return false;
      bool hit = false;
      reward = 0;
      for (size_t i = 0; i < b.miner_tx.vout.size(); ++i)
      {
        crypto::public_key out, want;
        if (!get_output_public_key(b.miner_tx.vout[i], out) || !crypto::derive_public_key(d, i, addr.m_spend_public_key, want))
          continue;
        if (out == want)
        {
          hit = true;
          reward += b.miner_tx.vout[i].amount;
        }
      }
      return hit;
    }
  }

  void sm64_board::set_enabled(bool on)
  {
    m_enabled = on;
    m_wake = true; // catches up the blocks missed while off
    MGINFO("SM64 board: " << (on ? "on" : "off"));
  }

  void sm64_board::block_added(uint64_t height)
  {
    if (!m_enabled)
      return;
    uint64_t cur = m_rewind.load();
    while (height < cur && !m_rewind.compare_exchange_weak(cur, height)) {}
    m_wake = true;
  }

  void sm64_board::init(const std::string &path, network_type nettype)
  {
    std::lock_guard<std::mutex> g(m_lock);
    m_path = path;
    m_nettype = nettype;
    m_saved_at = time(nullptr);
    board_file f;
    if (!epee::serialization::load_t_from_json_file(f, path))
      return;
    for (const auto &fi : f.items)
    {
      item it;
      std::string why;
      bool invalid = false;
      if (m_items.size() >= TOP_N || !check(fi.entry, it, why, invalid))
        continue;
      it.row.entry.heights.clear();
      if (fi.rewards.size() == fi.entry.heights.size())
        for (size_t i = 0; i < fi.entry.heights.size(); ++i)
          it.hits.push_back({fi.entry.heights[i], fi.rewards[i]});
      else
      {
        it.claims.assign(fi.entry.heights.rbegin(), fi.entry.heights.rend());
        it.lenient = true;
      }
      refresh(it);
      m_items.push_back(it);
    }
    m_saved_tip = f.tip;
    if (!epee::string_tools::hex_to_pod(f.tip_id, m_saved_tip_id))
      m_saved_tip = 0;
    rank();
    m_work = true;
    MINFO("SM64 board: " << m_items.size() << " entries from " << path);
  }

  bool sm64_board::cheap_check(const sm64_board_entry &e, std::string &why, bool &invalid) const
  {
    invalid = true;
    if (e.name.empty() || e.name.size() > 64)
    {
      why = "name must be 1-64 bytes";
      return false;
    }
    // well-formed UTF-8 without control characters
    size_t i = 0;
    while (i < e.name.size())
    {
      const unsigned char c = e.name[i];
      const size_t n = c < 0x80 ? 1 : (c >> 5) == 6 ? 2 : (c >> 4) == 14 ? 3 : (c >> 3) == 30 ? 4 : 0;
      bool ok = n != 0 && i + n <= e.name.size() && c >= 0x20 && c != 0x7f;
      for (size_t j = 1; ok && j < n; ++j)
        ok = ((unsigned char)e.name[i + j] >> 6) == 2;
      if (!ok)
      {
        why = "name must be UTF-8 without control characters";
        return false;
      }
      i += n;
    }
    if (e.address.size() > 200 || e.view_key.size() != 64 || e.signature.size() > 200)
    {
      why = "field size";
      return false;
    }
    if (e.heights.size() > MAX_HEIGHTS)
    {
      why = "too many heights";
      return false;
    }
    for (size_t k = 0; k < e.heights.size(); ++k)
      if (e.heights[k] == 0 || (k && e.heights[k] <= e.heights[k - 1]))
      {
        why = "heights must be ascending, from 1";
        return false;
      }
    invalid = false;
    if (e.timestamp > (uint64_t)time(nullptr) + FUTURE_SECONDS)
    {
      why = "timestamp in the future (check the clock)";
      return false;
    }
    return true;
  }

  bool sm64_board::check(const sm64_board_entry &e, item &out, std::string &why, bool &invalid) const
  {
    if (!cheap_check(e, why, invalid))
      return false;
    invalid = true;
    address_parse_info info;
    if (!get_account_address_from_str(info, m_nettype, e.address) || info.is_subaddress || info.has_payment_id)
    {
      why = "not a standard address of this network";
      return false;
    }
    crypto::secret_key view;
    crypto::public_key view_pub;
    if (!epee::string_tools::hex_to_pod(e.view_key, view) || !crypto::secret_key_to_public_key(view, view_pub) || view_pub != info.address.m_view_public_key)
    {
      why = "view key does not match the address";
      return false;
    }
    if (!signed_by_spend_key(signed_text(e), info.address, e.signature))
    {
      why = "bad signature (sign \"sm64coin-board:<timestamp>:<name>\" with the spend key)";
      return false;
    }
    invalid = false;
    out.row.entry = e;
    out.addr = info.address;
    out.view = view;
    return true;
  }

  bool sm64_board::block_pays(const item &it, Blockchain &bc, uint64_t h, uint64_t &reward) const
  {
    ++m_derivations;
    return pays(bc.get_db().get_block_from_height(h), it.addr, it.view, reward);
  }

  void sm64_board::refresh(item &it)
  {
    it.row.blocks = it.hits.size();
    it.row.reward = 0;
    for (const auto &x : it.hits)
      it.row.reward += x.reward;
    it.row.last_height = it.hits.empty() ? 0 : it.hits.back().height;
  }

  void sm64_board::add_hit(item &it, uint64_t h, uint64_t reward)
  {
    auto p = std::lower_bound(it.hits.begin(), it.hits.end(), h, [](const hit &x, uint64_t v) { return x.height < v; });
    if (p != it.hits.end() && p->height == h)
      return;
    it.hits.insert(p, {h, reward});
    refresh(it);
  }

  void sm64_board::drop_from(item &it, uint64_t height)
  {
    auto p = std::lower_bound(it.hits.begin(), it.hits.end(), height, [](const hit &x, uint64_t v) { return x.height < v; });
    it.hits.erase(p, it.hits.end());
    refresh(it);
  }

  void sm64_board::forget_after(uint64_t fork)
  {
    std::lock_guard<std::mutex> g(m_lock);
    for (auto *v : {&m_items, &m_pending})
      for (auto &it : *v)
        drop_from(it, fork);
    rank();
    m_dirty = true;
  }

  void sm64_board::rank()
  {
    std::sort(m_items.begin(), m_items.end(), [](const item &a, const item &b) { return better(a.row, b.row); });
    if (m_items.size() > TOP_N)
      m_items.resize(TOP_N);
  }

  void sm64_board::save(bool force) // m_scan_lock held
  {
    board_file f;
    std::string path;
    {
      std::lock_guard<std::mutex> g(m_lock);
      const uint64_t now = time(nullptr);
      if (m_path.empty() || !m_dirty || (!force && now < m_saved_at + SAVE_SECONDS))
        return;
      for (const auto &it : m_items)
      {
        file_item fi;
        fi.entry = it.row.entry;
        for (const auto &x : it.hits)
        {
          fi.entry.heights.push_back(x.height);
          fi.rewards.push_back(x.reward);
        }
        for (uint64_t c : it.claims) // not yet verified: kept as claims
        {
          fi.entry.heights.push_back(c);
          fi.rewards.clear();
        }
        f.items.push_back(std::move(fi));
      }
      if (m_have_next && !m_ids.empty())
      {
        f.tip = m_next;
        f.tip_id = epee::string_tools::pod_to_hex(m_ids.back());
      }
      path = m_path;
      m_dirty = false;
      m_saved_at = now;
    }
    epee::serialization::store_t_to_json_file(f, path);
  }

  void sm64_board::flush()
  {
    std::lock_guard<std::mutex> sg(m_scan_lock);
    save(true);
  }

  bool sm64_board::take(bucket &b, double cap, double per_sec, double n, uint64_t t_ms)
  {
    if (b.tokens < 0)
      b.tokens = cap;
    else
      b.tokens = std::min(cap, b.tokens + per_sec * (double)(t_ms - b.at_ms) / 1000.0);
    b.at_ms = t_ms;
    if (b.tokens < n)
      return false;
    b.tokens -= n;
    return true;
  }

  sm64_board::source_state &sm64_board::source_of(const std::string &s, uint64_t t_ms)
  {
    if (m_sources.size() > 2048)
      for (auto i = m_sources.begin(); i != m_sources.end();)
        i = (i->second.seen + 600000 < t_ms && i->first != "rpc") ? m_sources.erase(i) : std::next(i);
    source_state &st = m_sources[s];
    st.seen = t_ms;
    return st;
  }

  void sm64_board::strike(source_state &s, double n, uint64_t t_ms)
  {
    s.strikes = std::max(0.0, s.strikes - (double)(t_ms - s.strikes_at) / 30000.0) + n; // forgiven 1 per 30 s
    s.strikes_at = t_ms;
  }

  std::vector<sm64_board_entry> sm64_board::update(Blockchain &bc)
  {
    std::vector<sm64_board_entry> joined;
    if (!m_enabled)
      return joined;
    std::lock_guard<std::mutex> sg(m_scan_lock);
    const uint64_t t0 = now_ms();
    const bool poll = t0 >= m_poll_at;
    if (!m_wake.exchange(false) && !m_work && !poll && m_have_next)
    {
      save(false);
      return joined;
    }
    if (poll)
      m_poll_at = t0 + 60000;
    const uint64_t deadline = t0 + SLICE_MS;
    const uint64_t h = bc.get_current_blockchain_height();
    auto id_at = [&](uint64_t x) { return bc.get_block_id_by_height(x); };
    auto fill_ids = [&]() {
      m_ids.clear();
      for (uint64_t x = m_next > HISTORY ? m_next - HISTORY : 0; x < m_next; ++x)
        m_ids.push_back(id_at(x));
    };
    // Re-verify every hit (a claim that fails is dropped) instead of rescanning: a reorg deeper than HISTORY, or a stale file.
    auto reverify_all = [&]() {
      std::lock_guard<std::mutex> g(m_lock);
      for (auto *v : {&m_items, &m_pending})
        for (auto &it : *v)
        {
          for (auto x = it.hits.rbegin(); x != it.hits.rend(); ++x)
            it.claims.push_back(x->height);
          it.hits.clear();
          it.lenient = true;
          refresh(it);
        }
      m_work = true;
      m_dirty = true;
    };

    // 1. Where are we on the chain.
    if (!m_have_next)
    {
      if (m_saved_tip > 0 && m_saved_tip <= h && id_at(m_saved_tip - 1) == m_saved_tip_id && h - m_saved_tip <= MAX_CATCH_UP)
        m_next = m_saved_tip;
      else
      {
        if (m_saved_tip > 0 || !m_items.empty())
          reverify_all();
        m_next = h;
      }
      m_have_next = true;
      fill_ids();
    }
    else
    {
      const uint64_t rewind = m_rewind.exchange(UINT64_MAX);
      uint64_t fork = std::min(m_next, rewind);
      if (m_next > h || (m_next > 0 && (m_ids.empty() || id_at(m_next - 1) != m_ids.back())) || rewind < m_next)
      {
        const uint64_t base = m_next - m_ids.size(), top = std::min(m_next, h);
        bool found = false;
        for (uint64_t x = top; x-- > base;)
          if (id_at(x) == m_ids[x - base])
          {
            fork = std::min(fork, x + 1);
            found = true;
            break;
          }
        if (found && fork < base)
          found = false;
        if (found)
        {
          MINFO("SM64 board: reorg, forgetting the hits at height " << fork << " and above");
          forget_after(fork);
          m_next = fork;
          m_ids.resize(fork - base);
        }
        else
        {
          MWARNING("SM64 board: reorg deeper than " << HISTORY << ", verifying the hits again");
          reverify_all();
          m_next = h;
          fill_ids();
        }
      }
      if (h - m_next > MAX_CATCH_UP)
      {
        reverify_all();
        m_next = h;
        fill_ids();
      }
    }

    // 2. The blocks added since: each is checked against the board's view keys only.
    struct watcher { std::string address; account_public_address addr; crypto::secret_key view; };
    while (m_next < h && now_ms() < deadline)
    {
      std::vector<watcher> w;
      {
        std::lock_guard<std::mutex> g(m_lock);
        for (auto *v : {&m_items, &m_pending})
          for (const auto &it : *v)
            w.push_back({it.row.entry.address, it.addr, it.view});
      }
      ++m_derivations;
      const block b = bc.get_db().get_block_from_height(m_next);
      std::vector<std::pair<std::string, uint64_t>> got;
      if (m_next > 0)
        for (const auto &x : w)
        {
          uint64_t reward = 0;
          if (pays(b, x.addr, x.view, reward))
            got.push_back({x.address, reward});
        }
      if (!got.empty())
      {
        std::lock_guard<std::mutex> g(m_lock);
        for (const auto &x : got)
          for (auto *v : {&m_items, &m_pending})
            for (auto &it : *v)
              if (it.row.entry.address == x.first)
                add_hit(it, m_next, x.second);
        rank();
        m_dirty = true;
      }
      m_ids.push_back(id_at(m_next));
      if (m_ids.size() > HISTORY)
        m_ids.pop_front();
      ++m_next;
    }

    // 3. Verify claimed heights: one block read + derivation each, random order, the first lie refuses the entry.
    struct job { std::string address; account_public_address addr; crypto::secret_key view; std::vector<uint64_t> claims; bool lenient; std::vector<hit> found; bool lie = false; };
    std::vector<job> jobs;
    {
      std::lock_guard<std::mutex> g(m_lock);
      for (auto *v : {&m_pending, &m_items})
        for (const auto &it : *v)
          if (!it.claims.empty())
            jobs.push_back({it.row.entry.address, it.addr, it.view, it.claims, it.lenient, {}, false});
    }
    for (auto &j : jobs)
      while (!j.claims.empty() && !j.lie && now_ms() < deadline)
      {
        const uint64_t x = j.claims.back();
        j.claims.pop_back();
        if (x >= h)
          continue; // not on our chain (yet)
        item probe;
        probe.addr = j.addr;
        probe.view = j.view;
        uint64_t reward = 0;
        if (block_pays(probe, bc, x, reward))
          j.found.push_back({x, reward});
        else if (!j.lenient)
          j.lie = true;
      }
    {
      std::lock_guard<std::mutex> g(m_lock);
      for (const auto &j : jobs)
      {
        for (auto *v : {&m_pending, &m_items})
          for (auto it = v->begin(); it != v->end(); ++it)
            if (it->row.entry.address == j.address)
            {
              if (j.lie)
              {
                MINFO("SM64 board: " << j.address.substr(0, 12) << "... claimed a height it did not mine, refused");
                v->erase(it);
              }
              else
              {
                it->claims = j.claims;
                for (const auto &f : j.found)
                  add_hit(*it, f.height, f.reward);
              }
              break;
            }
      }
      // 4. Entries whose claims are all verified join the board (or are dropped).
      const uint64_t now = time(nullptr);
      for (auto p = m_pending.begin(); p != m_pending.end();)
      {
        if (!p->claims.empty() && p->changed_at + 3600 > now)
        {
          ++p;
          continue;
        }
        const std::string addr = p->row.entry.address;
        p->changed_at = 0; // joining does not start the rename timer
        if (p->claims.empty() && !p->hits.empty() && std::none_of(m_items.begin(), m_items.end(), [&](const item &x) { return x.row.entry.address == addr; }))
        {
          m_items.push_back(*p);
          rank();
          auto on = std::find_if(m_items.begin(), m_items.end(), [&](const item &x) { return x.row.entry.address == addr; });
          if (on != m_items.end())
          {
            sm64_board_entry e = on->row.entry;
            for (const auto &x : on->hits)
              e.heights.push_back(x.height);
            joined.push_back(e);
            m_dirty = true;
          }
        }
        p = m_pending.erase(p);
      }
      rank();
      bool work = false;
      for (auto *v : {&m_pending, &m_items})
        for (const auto &it : *v)
          work = work || !it.claims.empty();
      m_work = work;
    }
    if (m_next < h)
      m_wake = true; // more blocks to check next time
    save(false);
    return joined;
  }

  sm64_board_result sm64_board::offer(const std::vector<sm64_board_entry> &in, Blockchain &bc, const std::string &source)
  {
    sm64_board_result res;
    if (!m_enabled)
    {
      res.disabled = true;
      res.why = "the leaderboard is turned off on this node";
      return res;
    }
    const bool rpc = source == "rpc";
    const uint64_t t_ms = now_ms(), now = time(nullptr);
    const uint64_t h = bc.get_current_blockchain_height();
    size_t total_heights = 0;
    for (const auto &e : in)
      total_heights += e.heights.size();
    {
      std::lock_guard<std::mutex> g(m_lock);
      source_state &s = source_of(source, t_ms);
      if (!rpc && (!take(s.msgs, 10, 0.1, 1, t_ms) || total_heights > MAX_MESSAGE_HEIGHTS)) // honest peers send a few a minute
      {
        strike(s, 1, t_ms);
        res.why = "too many messages";
        res.abuse = s.strikes >= 10;
        return res;
      }
    }
    for (const auto &e : in)
    {
      bool rename = false;
      crypto::hash eh = crypto::null_hash;
      // 1. Cheap checks and the budgets, under the lock; no crypto here.
      {
        std::lock_guard<std::mutex> g(m_lock);
        source_state &s = source_of(source, t_ms);
        auto known = std::find_if(m_items.begin(), m_items.end(), [&](const item &it) { return it.row.entry.address == e.address; });
        if (known != m_items.end())
        {
          const auto &k = known->row.entry;
          // A rename: a later signed timestamp (ties: the smaller name) with a new name.
          if (e.timestamp < k.timestamp || (e.timestamp == k.timestamp && e.name >= k.name) || e.name == k.name)
            continue;
          if (known->changed_at + RENAME_SECONDS > now)
          {
            res.why = "renamed too recently (once per " + std::to_string(RENAME_SECONDS / 60) + " minutes)";
            continue;
          }
          rename = true;
        }
        else
        {
          auto q = std::find_if(m_pending.begin(), m_pending.end(), [&](const item &it) { return it.row.entry.address == e.address; });
          if (q != m_pending.end() && q->row.entry.timestamp >= e.timestamp)
          {
            res.queued = true;
            continue;
          }
          if (e.heights.empty())
          {
            res.why = "update your wallet: joining needs the heights of the blocks you mined (heights)";
            continue;
          }
        }
        std::string w;
        bool invalid = false;
        if (!cheap_check(e, w, invalid))
        {
          res.why = w;
          if (invalid) strike(s, 2, t_ms);
          continue;
        }
        if (!rename)
        {
          if (e.heights.back() >= h)
          {
            res.why = "a height is above this node's chain (it is still syncing, or the height is wrong)";
            continue;
          }
          if (m_items.size() >= TOP_N && e.heights.size() < m_items.back().row.blocks)
          {
            res.why = "not in the top 50 (" + std::to_string(e.heights.size()) + " blocks; the 50th has " + std::to_string(m_items.back().row.blocks) + ")";
            continue;
          }
        }
        if (!rpc)
        {
          eh = entry_hash(e);
          auto seen = m_seen.find(eh);
          if (seen != m_seen.end() && seen->second > now)
            continue; // judged already
        }
        // the crypto below is paid from these
        if (!take(s.entries, rpc ? 60 : 150, rpc ? 1.0 : 2.5, 1, t_ms) || (!rpc && !take(m_p2p_verify, 300, 5.0, 1, t_ms)))
        {
          res.why = "busy (too many entries; try again in a minute)";
          if (!rpc) strike(s, 0.25, t_ms);
          continue;
        }
        if (!rpc)
        {
          if (m_seen.size() >= SEEN_MAX)
          {
            for (auto i = m_seen.begin(); i != m_seen.end();)
              i = i->second <= now ? m_seen.erase(i) : std::next(i);
            if (m_seen.size() >= SEEN_MAX)
              m_seen.clear();
          }
          m_seen[eh] = now + SEEN_SECONDS;
        }
      }
      // 2. Verify: view key and signature, outside the lock.
      item it;
      std::string w;
      bool invalid = false;
      if (!check(e, it, w, invalid))
      {
        res.why = w;
        if (invalid)
        {
          std::lock_guard<std::mutex> g(m_lock);
          strike(source_of(source, t_ms), 2, t_ms);
        }
        continue;
      }
      std::lock_guard<std::mutex> g(m_lock);
      if (rename)
      {
        auto known = std::find_if(m_items.begin(), m_items.end(), [&](const item &x) { return x.row.entry.address == e.address; });
        if (known == m_items.end() || e.timestamp < known->row.entry.timestamp || e.name == known->row.entry.name || known->changed_at + RENAME_SECONDS > now)
          continue;
        known->row.entry = e;
        known->row.entry.heights.clear();
        known->changed_at = now;
        sm64_board_entry out = e;
        for (const auto &x : known->hits)
          out.heights.push_back(x.height);
        res.changed.push_back(out);
        m_dirty = true; // written by update(), at most once a minute
        continue;
      }
      // 3. A new address: queued; update() verifies its heights, then it joins.
      if (std::any_of(m_items.begin(), m_items.end(), [&](const item &x) { return x.row.entry.address == e.address; }))
        continue;
      auto q = std::find_if(m_pending.begin(), m_pending.end(), [&](const item &x) { return x.row.entry.address == e.address; });
      size_t claimed = 0, mine = 0;
      for (const auto &p : m_pending)
      {
        claimed += p.claims.size();
        mine += p.source == source;
      }
      if (q != m_pending.end())
      {
        claimed -= q->claims.size();
        mine -= q->source == source;
      }
      if ((q == m_pending.end() && m_pending.size() >= PENDING_MAX) || mine >= (rpc ? PENDING_MAX * 3 / 4 : PENDING_PER_SOURCE) || claimed + e.heights.size() > PENDING_HEIGHTS)
      {
        res.why = "busy (too many entries are being verified; try again in a minute)";
        continue;
      }
      it.row.entry.heights.clear();
      it.claims.assign(e.heights.begin(), e.heights.end());
      std::shuffle(it.claims.begin(), it.claims.end(), std::mt19937_64(std::random_device{}()));
      it.changed_at = now;
      it.source = source;
      if (q != m_pending.end())
        *q = std::move(it);
      else
        m_pending.push_back(std::move(it));
      m_work = true;
      res.queued = true;
    }
    return res;
  }

  std::vector<sm64_board_row> sm64_board::rows() const
  {
    std::lock_guard<std::mutex> g(m_lock);
    std::vector<sm64_board_row> v;
    for (const auto &it : m_items)
      v.push_back(it.row);
    return v;
  }

  std::vector<sm64_board_entry> sm64_board::entries() const
  {
    std::lock_guard<std::mutex> g(m_lock);
    std::vector<sm64_board_entry> v;
    for (const auto &it : m_items)
    {
      sm64_board_entry e = it.row.entry;
      e.heights.clear();
      for (const auto &x : it.hits)
        e.heights.push_back(x.height);
      v.push_back(std::move(e));
    }
    return v;
  }
}
