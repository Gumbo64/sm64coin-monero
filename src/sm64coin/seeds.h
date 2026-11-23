// SM64COIN: the built-in seed nodes (p2p). Header-only: the p2p library doesn't link the PoW glue.
//
// Every node keeps these connected as priority peers (unless --add-exclusive-node is given, or
// SM64COIN_NO_SEEDS is set), so a node started by anything (the launcher, the wallet app, the
// scripts) finds the network without --add-peer. A hostname that doesn't resolve is skipped.
// A seed must reach the node's p2p port directly (a DNS-only record, not an HTTP proxy).
#pragma once

#include <cstdlib>
#include <string>
#include <vector>
#include "cryptonote_config.h"

namespace sm64coin
{
  inline std::vector<std::string> seed_nodes(cryptonote::network_type nettype)
  {
    if (std::getenv("SM64COIN_NO_SEEDS"))
      return {};
    if (nettype == cryptonote::MAINNET)
      return {"p2p.eboy.au:16480"};
    return {};
  }
}
