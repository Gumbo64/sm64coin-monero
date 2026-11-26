// SM64COIN v0.4.2: the coinbase unlock window is 72 blocks below SM64COIN_UNLOCK6_HEIGHT and 6 from it.

#include "gtest/gtest.h"

#include <sstream>
#include <vector>
#include <string>
#include <boost/program_options.hpp>
#include "cryptonote_config.h"
#include "cryptonote_basic/account.h"
#include "cryptonote_core/cryptonote_tx_utils.h"
#include "cryptonote_core/tx_pool.h"
#define private public // the check under test is a private member of Blockchain
#include "cryptonote_core/blockchain.h"
#undef private

TEST(sm64coin_unlock, window_by_height)
{
  const uint64_t h = SM64COIN_UNLOCK6_HEIGHT;
  EXPECT_EQ(72u, sm64coin_mined_money_unlock_window(0));
  if (h > 0)
  {
    EXPECT_EQ(72u, sm64coin_mined_money_unlock_window(1));
    EXPECT_EQ(72u, sm64coin_mined_money_unlock_window(h - 1));
  }
  EXPECT_EQ(6u, sm64coin_mined_money_unlock_window(h));
  EXPECT_EQ(6u, sm64coin_mined_money_unlock_window(h + 1));
  EXPECT_EQ(6u, sm64coin_mined_money_unlock_window(CRYPTONOTE_MAX_BLOCK_NUMBER));
}

TEST(sm64coin_unlock, legacy_constant_and_spendable_age_unchanged)
{
  EXPECT_EQ(72, CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW);
  EXPECT_EQ(3, CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE);
  EXPECT_GT(CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW, CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE);
  EXPECT_GE(SM64COIN_MINED_MONEY_UNLOCK_WINDOW_NEW, CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE);
}

// The consensus check (Blockchain::prevalidate_miner_transaction) against the block construction
// (construct_miner_tx), on both sides of the activation height.
namespace
{
  // Blockchain and the pool refer to each other (as in cryptonote::core); the check below touches neither.
  struct unlock_fixture
  {
    cryptonote::tx_memory_pool pool;
    cryptonote::Blockchain bc;
    unlock_fixture(): pool(bc), bc(pool) {}
  };

  cryptonote::block block_with_unlock(const cryptonote::account_base &acc, uint64_t height, int64_t unlock_delta_from_height)
  {
    cryptonote::block b;
    EXPECT_TRUE(cryptonote::construct_miner_tx(height, 0, 0, 300000, 0, acc.get_keys().m_account_address, b.miner_tx, cryptonote::blobdata(), 999, 16));
    b.miner_tx.unlock_time = height + unlock_delta_from_height;
    return b;
  }
}

TEST(sm64coin_unlock, construct_miner_tx_uses_the_window_in_force)
{
  cryptonote::account_base acc; acc.generate();
  const uint64_t H = SM64COIN_UNLOCK6_HEIGHT;
  for (uint64_t height : {uint64_t(1), uint64_t(H - 1), uint64_t(H), uint64_t(H + 1), uint64_t(H + 100)})
  {
    cryptonote::transaction tx;
    ASSERT_TRUE(cryptonote::construct_miner_tx(height, 0, 0, 300000, 0, acc.get_keys().m_account_address, tx, cryptonote::blobdata(), 999, 16));
    EXPECT_EQ(height + (height >= H ? 6 : 72), tx.unlock_time) << "height " << height;
  }
}

TEST(sm64coin_unlock, consensus_accepts_only_the_window_in_force)
{
  unlock_fixture f;
  cryptonote::account_base acc; acc.generate();
  const uint64_t H = SM64COIN_UNLOCK6_HEIGHT;
  ASSERT_GT(H, 2u);
  const uint8_t hf = 16;
  // below the activation height: 72 accepted, 6 rejected (v0.4.1 behaviour unchanged)
  for (uint64_t height : {uint64_t(1), uint64_t(H - 1)})
  {
    EXPECT_TRUE (f.bc.prevalidate_miner_transaction(block_with_unlock(acc, height, 72), height, hf)) << height;
    EXPECT_FALSE(f.bc.prevalidate_miner_transaction(block_with_unlock(acc, height, 6), height, hf)) << height;
  }
  // at and above it: 6 accepted, 72 rejected
  for (uint64_t height : {uint64_t(H), uint64_t(H + 1), uint64_t(H + 1000)})
  {
    EXPECT_TRUE (f.bc.prevalidate_miner_transaction(block_with_unlock(acc, height, 6), height, hf)) << height;
    EXPECT_FALSE(f.bc.prevalidate_miner_transaction(block_with_unlock(acc, height, 72), height, hf)) << height;
  }
  // a block built by construct_miner_tx always passes its own height's check
  for (uint64_t height : {uint64_t(5), uint64_t(H - 1), uint64_t(H), uint64_t(H + 5)})
  {
    cryptonote::block b;
    ASSERT_TRUE(cryptonote::construct_miner_tx(height, 0, 0, 300000, 0, acc.get_keys().m_account_address, b.miner_tx, cryptonote::blobdata(), 999, 16));
    EXPECT_TRUE(f.bc.prevalidate_miner_transaction(b, height, hf)) << height;
  }
}
