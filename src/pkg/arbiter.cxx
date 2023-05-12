#include "../../include/pkg/arbiter.hpp"
#include "../../include/drivers/repl_driver.hpp"
#include "../../include/pkg/election.hpp"
#include "../../include-shared/keyloaders.hpp"
#include "../../include-shared/logger.hpp"

/*
Syntax to use logger: 
  CUSTOM_LOG(lg, debug) << "your message"
See logger.hpp for more modes besides 'debug'
*/
namespace {
  src::severity_logger<logging::trivial::severity_level> lg;
}

/**
 * Constructor
 */
ArbiterClient::ArbiterClient(ArbiterConfig arbiter_config,
                             CommonConfig common_config) {
  // Make shared variables.
  this->arbiter_config = arbiter_config;
  this->common_config = common_config;
  this->num_candidates = std::stoi(common_config.num_candidates);
  this->k = std::stoi(common_config.k);
  this->cli_driver = std::make_shared<CLIDriver>();
  this->crypto_driver = std::make_shared<CryptoDriver>();
  this->db_driver = std::make_shared<DBDriver>();
  this->db_driver->open(this->common_config.db_path);
  this->db_driver->init_tables();
  this->cli_driver->init();

  // Load arbiter keys.
  try {
    LoadInteger(arbiter_config.arbiter_secret_key_path,
                &this->EG_arbiter_secret_key);
    LoadInteger(arbiter_config.arbiter_public_key_path,
                &this->EG_arbiter_public_key_i);
    LoadElectionPublicKey(common_config.arbiter_public_key_paths,
                          &this->EG_arbiter_public_key);
  } catch (CryptoPP::FileStore::OpenErr) {
    this->cli_driver->print_warning(
        "Could not find arbiter keys; you might consider generating some!");
  }

  // Load registrar public key
  try {
    LoadDSAPublicKey(common_config.registrar_verification_key_path,
                     this->DSA_registrar_verification_key);
  } catch (CryptoPP::FileStore::OpenErr) {
    this->cli_driver->print_warning("Error loading registrar public key; "
                                    "application may be non-functional.");
  }

  // Load tallyer public key
  try {
    LoadDSAPublicKey(common_config.tallyer_verification_key_path,
                     this->DSA_tallyer_verification_key);
  } catch (CryptoPP::FileStore::OpenErr) {
    this->cli_driver->print_warning(
        "Error loading tallyer public key; application may be non-functional.");
  }
}

void ArbiterClient::run() {
  // Start REPL
  REPLDriver<ArbiterClient> repl = REPLDriver<ArbiterClient>(this);
  repl.add_action("keygen", "keygen", &ArbiterClient::HandleKeygen);
  repl.add_action("adjudicate", "adjudicate", &ArbiterClient::HandleAdjudicate);
  repl.run();
}

/**
 * Handle generating election keys
 */
void ArbiterClient::HandleKeygen(std::string _) {
  // Generate keys
  this->cli_driver->print_info("Generating keys, this may take some time...");
  std::pair<CryptoPP::Integer, CryptoPP::Integer> keys =
      this->crypto_driver->EG_generate();

  // Save keys
  SaveInteger(this->arbiter_config.arbiter_secret_key_path, keys.first);
  SaveInteger(this->arbiter_config.arbiter_public_key_path, keys.second);
  LoadInteger(arbiter_config.arbiter_secret_key_path,
              &this->EG_arbiter_secret_key);
  LoadInteger(arbiter_config.arbiter_public_key_path,
              &this->EG_arbiter_public_key_i);
  LoadElectionPublicKey(common_config.arbiter_public_key_paths,
                        &this->EG_arbiter_public_key);
  this->cli_driver->print_success("Keys succesfully generated and saved!");
}

/**
 * Handle partial decryption. This function:
 * 1) Update the ElectionPublicKey to the most up to date.
 * 2) Gets all of the votes from the database
 * 3) Verifies all of the vote ZKPs and signatures
 * 4) Combines all valid votes into one vote
 * 5) Partially decrypts the combined vote
 * 6) Publishes the decryption and zkp to the database
 */
void ArbiterClient::HandleAdjudicate(std::string _) {
  // TODO: implement me!

  // update the ElectionPublicKey
  LoadElectionPublicKey(common_config.arbiter_public_key_paths, &this->EG_arbiter_public_key);

  std::vector<VoteRow> votes = this->db_driver->all_votes();
  std::vector<VoteRow> valid_votes;

  for (int i=0; i<votes.size(); i++) {
    std::pair<Votes_Struct, VoteZKPs_Struct> votes_pair = std::make_pair(votes[i].votes, votes[i].zkps);
    if (!(ElectionClient::VerifyVoteZKPs(votes_pair, this->EG_arbiter_public_key))) {
      continue;
    }

    std::vector<unsigned char> vote_info_str = 
      concat_votes_and_zkps(votes[i].votes, votes[i].zkps, votes[i].vote_count, votes[i].count_zkps);
    if (!(this->crypto_driver->DSA_verify(this->DSA_tallyer_verification_key, vote_info_str, votes[i].tallyer_signature))) {
      continue;
    }

    valid_votes.push_back(votes[i]);
  }

  Votes_Struct combined_votes = ElectionClient::CombineVotes(valid_votes, this->num_candidates);

  PartialDecryptionRow partial_dec_row;
  partial_dec_row.arbiter_id = this->arbiter_config.arbiter_id;
  partial_dec_row.arbiter_vk_path = this->arbiter_config.arbiter_public_key_path;
  
  std::pair<PartialDecryptions_Struct, DecryptionZKPs_Struct> p = 
    ElectionClient::PartialDecryptions(combined_votes, this->EG_arbiter_public_key_i, this->EG_arbiter_secret_key);
  partial_dec_row.decs = p.first;
  partial_dec_row.zkps = p.second;

  this->db_driver->insert_partial_decryption(partial_dec_row);
}
