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

class VoterClient {
public:
  VoterClient(std::shared_ptr<NetworkDriver> network_driver,
              std::shared_ptr<CryptoDriver> crypto_driver,
              VoterConfig voter_config, CommonConfig common_config);
  void run();
  std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock>
  HandleKeyExchange(CryptoPP::DSA::PublicKey verification_key);
  void HandleRegister(std::string input);
  void HandleVote(std::string input);
  void HandleVerify(std::string input);
  std::tuple<std::vector<CryptoPP::Integer>, std::vector<CryptoPP::Integer>, bool> DoVerify();

private:
  std::string id;
  RegistrarToVoter_Certificate_Message certificate;

  VoterConfig voter_config;
  CommonConfig common_config;
  int num_candidates;
  int k;
  std::shared_ptr<CLIDriver> cli_driver;
  std::shared_ptr<CryptoDriver> crypto_driver;
  std::shared_ptr<DBDriver> db_driver;
  std::shared_ptr<NetworkDriver> network_driver;

  CryptoPP::Integer EG_arbiter_public_key; // The election's EG public key
  CryptoPP::SecByteBlock AES_key;
  CryptoPP::SecByteBlock HMAC_key;

  CryptoPP::DSA::PrivateKey DSA_voter_signing_key;
  CryptoPP::DSA::PublicKey DSA_voter_verification_key;
  CryptoPP::DSA::PublicKey DSA_registrar_verification_key;
  CryptoPP::DSA::PublicKey DSA_tallyer_verification_key;
};
