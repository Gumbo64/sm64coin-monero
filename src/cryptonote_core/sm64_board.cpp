// SM64COIN: see sm64_board.h.
#include "sm64_board.h"

#include <algorithm>
#include <ctime>

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
    struct board_file
    {
      std::vector<sm64_board_entry> entries;
      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(entries)
      END_KV_SERIALIZE_MAP()
    };

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
  }

  void sm64_board::init(const std::string &path, network_type nettype)
  {
    std::lock_guard<std::mutex> g(m_lock);
    m_path = path;
    m_nettype = nettype;
    board_file f;
    if (!epee::serialization::load_t_from_json_file(f, path))
      return;
    for (const auto &e : f.entries)
    {
      item it;
      std::string why;
      if (check(e, it, why) && m_items.size() < TOP_N)
        m_items.push_back(it);
    }
    MINFO("SM64 board: " << m_items.size() << " entries from " << path);
  }

  bool sm64_board::check(const sm64_board_entry &e, item &out, std::string &why) const
  {
    if (e.name.empty() || e.name.size() > 64)
    {
      why = "name must be 1-64 bytes";
      return false;
    }
    for (unsigned char c : e.name)
      if (c < 0x20 || c == 0x7f)
      {
        why = "name has control characters";
        return false;
      }
    if (e.address.size() > 200 || e.view_key.size() != 64 || e.signature.size() > 200)
    {
      why = "field size";
      return false;
    }
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
    if (e.timestamp > (uint64_t)time(nullptr) + 2 * 3600)
    {
      why = "timestamp in the future";
      return false;
    }
    if (!signed_by_spend_key(signed_text(e), info.address, e.signature))
    {
      why = "bad signature (sign \"sm64coin-board:<timestamp>:<name>\" with the spend key)";
      return false;
    }
    out.row.entry = e;
    out.addr = info.address;
    out.view = view;
    return true;
  }

  void sm64_board::count(item &it, Blockchain &bc, uint64_t from, uint64_t to) const
  {
    for (uint64_t h = std::max<uint64_t>(from, 1); h < to; ++h)
    {
      const block b = bc.get_db().get_block_from_height(h);
      const crypto::public_key r = get_tx_pub_key_from_extra(b.miner_tx);
      crypto::key_derivation d;
      if (r == crypto::null_pkey || !crypto::generate_key_derivation(r, it.view, d))
        continue;
      bool hit = false;
      for (size_t i = 0; i < b.miner_tx.vout.size(); ++i)
      {
        crypto::public_key out, want;
        if (!get_output_public_key(b.miner_tx.vout[i], out) || !crypto::derive_public_key(d, i, it.addr.m_spend_public_key, want))
          continue;
        if (out == want)
        {
          hit = true;
          it.row.reward += b.miner_tx.vout[i].amount;
        }
      }
      if (hit)
      {
        it.row.blocks += 1;
        it.row.last_height = h;
      }
    }
  }

  void sm64_board::rank()
  {
    std::sort(m_items.begin(), m_items.end(), [](const item &a, const item &b) { return better(a.row, b.row); });
    if (m_items.size() > TOP_N)
      m_items.resize(TOP_N);
  }

  void sm64_board::save() const
  {
    if (m_path.empty())
      return;
    board_file f;
    for (const auto &it : m_items)
      f.entries.push_back(it.row.entry);
    epee::serialization::store_t_to_json_file(f, m_path);
  }

  void sm64_board::update(Blockchain &bc)
  {
    std::lock_guard<std::mutex> g(m_lock);
    const uint64_t h = bc.get_current_blockchain_height();
    uint64_t from = m_scanned;
    if (m_scanned == 0 || m_scanned > h || bc.get_block_id_by_height(m_scanned - 1) != m_top)
    {
      from = 0;
      for (auto &it : m_items)
        it.row.blocks = it.row.reward = it.row.last_height = 0;
    }
    if (from >= h)
      return;
    for (auto &it : m_items)
      count(it, bc, from, h);
    m_scanned = h;
    m_top = bc.get_block_id_by_height(h - 1);
    rank();
  }

  std::vector<sm64_board_entry> sm64_board::offer(const std::vector<sm64_board_entry> &in, Blockchain &bc, std::string *why)
  {
    std::vector<sm64_board_entry> changed;
    std::lock_guard<std::mutex> g(m_lock);
    const uint64_t h = bc.get_current_blockchain_height();
    const uint64_t now = time(nullptr);
    m_scans.erase(std::remove_if(m_scans.begin(), m_scans.end(), [now](uint64_t t) { return t + 60 < now; }), m_scans.end());
    bool dirty = false;
    for (const auto &e : in)
    {
      auto known = std::find_if(m_items.begin(), m_items.end(), [&](const item &it) { return it.row.entry.address == e.address; });
      if (known != m_items.end())
      {
        const auto &k = known->row.entry;
        // A rename: a later signed timestamp (ties: the smaller name).
        if (e.timestamp < k.timestamp || (e.timestamp == k.timestamp && e.name >= k.name))
          continue;
        item it;
        std::string w;
        if (!check(e, it, w))
        {
          if (why) *why = w;
          continue;
        }
        known->row.entry = e;
        changed.push_back(e);
        dirty = true;
        continue;
      }
      // A new address: one full count of the chain, at most 30 a minute.
      if (m_scans.size() >= 30)
      {
        if (why) *why = "busy (too many new entries this minute)";
        continue;
      }
      item it;
      std::string w;
      if (!check(e, it, w))
      {
        if (why) *why = w;
        continue;
      }
      m_scans.push_back(now);
      // Counted to the board's scan height, so the board's own update adds
      // the rest like everyone else's (and a fresh board counts it all).
      count(it, bc, 0, m_scanned ? m_scanned : h);
      if (it.row.blocks == 0)
      {
        if (why) *why = "this address has not mined a block";
        continue;
      }
      m_items.push_back(it);
      rank();
      if (std::any_of(m_items.begin(), m_items.end(), [&](const item &x) { return x.row.entry.address == e.address; }))
      {
        changed.push_back(e);
        dirty = true;
      }
      else if (why)
        *why = "not in the top 50";
    }
    if (dirty)
      save();
    return changed;
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
      v.push_back(it.row.entry);
    return v;
  }
}
