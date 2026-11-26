// SM64COIN v0.5: the coinbase unlock window is 6 blocks (v0.3-v0.4: 72).

#include "gtest/gtest.h"

#include "cryptonote_config.h"
#include "cryptonote_basic/account.h"
#include "cryptonote_core/cryptonote_tx_utils.h"
#include "cryptonote_core/tx_pool.h"
#define private public // the check under test is a private member of Blockchain
#include "cryptonote_core/blockchain.h"
#undef private

TEST(sm64coin_unlock, window_is_six_and_not_below_the_spendable_age)
{
  EXPECT_EQ(6, CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW);
  EXPECT_EQ(3, CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE);
  EXPECT_GE(CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW, CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE);
}

namespace
{
  // Blockchain and the pool refer to each other (as in cryptonote::core); the check below touches neither.
  struct unlock_fixture
  {
    cryptonote::tx_memory_pool pool;
    cryptonote::Blockchain bc;
    unlock_fixture(): pool(bc), bc(pool) {}
  };

  cryptonote::block block_with_unlock(const cryptonote::account_base &acc, uint64_t height, uint64_t unlock_delta_from_height)
  {
    cryptonote::block b;
    EXPECT_TRUE(cryptonote::construct_miner_tx(height, 0, 0, 300000, 0, acc.get_keys().m_account_address, b.miner_tx, cryptonote::blobdata(), 999, 16));
    b.miner_tx.unlock_time = height + unlock_delta_from_height;
    return b;
  }
}

TEST(sm64coin_unlock, construct_miner_tx_locks_for_six_blocks)
{
  cryptonote::account_base acc; acc.generate();
  for (uint64_t height : {uint64_t(1), uint64_t(100), uint64_t(100000)})
  {
    cryptonote::transaction tx;
    ASSERT_TRUE(cryptonote::construct_miner_tx(height, 0, 0, 300000, 0, acc.get_keys().m_account_address, tx, cryptonote::blobdata(), 999, 16));
    EXPECT_EQ(height + 6, tx.unlock_time) << "height " << height;
  }
}

TEST(sm64coin_unlock, consensus_accepts_only_six)
{
  unlock_fixture f;
  cryptonote::account_base acc; acc.generate();
  const uint8_t hf = 16;
  for (uint64_t height : {uint64_t(1), uint64_t(100), uint64_t(100000)})
  {
    EXPECT_TRUE (f.bc.prevalidate_miner_transaction(block_with_unlock(acc, height, 6), height, hf)) << height;
    EXPECT_FALSE(f.bc.prevalidate_miner_transaction(block_with_unlock(acc, height, 72), height, hf)) << height;
    EXPECT_FALSE(f.bc.prevalidate_miner_transaction(block_with_unlock(acc, height, 5), height, hf)) << height;
    EXPECT_FALSE(f.bc.prevalidate_miner_transaction(block_with_unlock(acc, height, 7), height, hf)) << height;
  }
}
