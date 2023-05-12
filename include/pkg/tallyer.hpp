#pragma once

#include <crypto++/cryptlib.h>
#include <crypto++/dh.h>
#include <crypto++/dh2.h>
#include <crypto++/dsa.h>
#include <crypto++/integer.h>
#include <crypto++/nbtheory.h>
#include <crypto++/osrng.h>

#include "../../include-shared/config.hpp"
#include "../../include-shared/messages.hpp"
#include "../../include/drivers/cli_driver.hpp"
#include "../../include/drivers/crypto_driver.hpp"
#include "../../include/drivers/db_driver.hpp"
#include "../../include/drivers/network_driver.hpp"

class TallyerClient {
public:
  TallyerClient(TallyerConfig tallyer_config, CommonConfig common_config);
  void run(int port);
  std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock>
  HandleKeyExchange(std::shared_ptr<NetworkDriver> network_driver,
                    std::shared_ptr<CryptoDriver> crypto_driver);
  void HandleTally(std::shared_ptr<NetworkDriver> network_driver,
                   std::shared_ptr<CryptoDriver> crypto_driver);

private:
  TallyerConfig tallyer_config;
  CommonConfig common_config;
  int num_candidates;
  int k;
  std::shared_ptr<CLIDriver> cli_driver;
  std::shared_ptr<DBDriver> db_driver;

  CryptoPP::Integer EG_arbiter_public_key; // The election's EG public key
  CryptoPP::DSA::PublicKey DSA_registrar_verification_key;
  CryptoPP::DSA::PrivateKey DSA_tallyer_signing_key;
  CryptoPP::DSA::PublicKey DSA_tallyer_verification_key;

  void ListenForConnections(int port);
};
