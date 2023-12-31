#include "../../include/pkg/voter.hpp"
#include "../../include/drivers/crypto_driver.hpp"
#include "../../include/drivers/repl_driver.hpp"
#include "../../include/pkg/election.hpp"
#include "../../include-shared/keyloaders.hpp"
#include "../../include-shared/logger.hpp"
#include "util.hpp"

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
VoterClient::VoterClient(std::shared_ptr<NetworkDriver> network_driver,
                         std::shared_ptr<CryptoDriver> crypto_driver,
                         VoterConfig voter_config, CommonConfig common_config) {
  // Make shared variables.
  this->voter_config = voter_config;
  this->common_config = common_config;
  this->num_candidates = std::stoi(common_config.num_candidates);
  this->k = std::stoi(common_config.k);
  this->network_driver = network_driver;
  this->crypto_driver = crypto_driver;
  this->cli_driver = std::make_shared<CLIDriver>();
  this->db_driver = std::make_shared<DBDriver>();
  this->db_driver->open(this->common_config.db_path);
  this->db_driver->init_tables();
  this->cli_driver->init();
  initLogger();

  // Load ID.
  this->id = voter_config.voter_id;

  // Load voter keys
  try {
    LoadDSAPrivateKey(voter_config.voter_signing_key_path,
                      this->DSA_voter_signing_key);
    LoadCertificate(voter_config.voter_certificate_path, this->certificate);
    this->DSA_voter_verification_key = this->certificate.verification_key;
  } catch (CryptoPP::FileStore::OpenErr) {
    this->cli_driver->print_warning(
        "Error loading keys, you may consider registering again!");
  } catch (std::runtime_error &_) {
    this->cli_driver->print_warning(
        "Error loading keys, you may consider registering again!");
  }

  // Load election public key
  try {
    LoadElectionPublicKey(common_config.arbiter_public_key_paths,
                          &this->EG_arbiter_public_key);
  } catch (CryptoPP::FileStore::OpenErr) {
    this->cli_driver->print_warning("Error loading arbiter public keys; "
                                    "application may be non-functional.");
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

/**
 * Run REPL
 */
void VoterClient::run() {
  // Start REPL
  REPLDriver<VoterClient> repl = REPLDriver<VoterClient>(this);
  repl.add_action("register", "register <address> <port>",
                  &VoterClient::HandleRegister);
  repl.add_action("vote", "vote <address> <port> {0, 1}, ..., {0, 1}",
                  &VoterClient::HandleVote);
  repl.add_action("verify", "verify", &VoterClient::HandleVerify);
  repl.run();
}

/**
 * Key exchange with either registrar or tallyer
 */
std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock>
VoterClient::HandleKeyExchange(CryptoPP::DSA::PublicKey verification_key) {
  // Generate private/public DH values
  auto dh_values = this->crypto_driver->DH_initialize();

  // Send g^a
  UserToServer_DHPublicValue_Message user_public_value_s;
  user_public_value_s.public_value = std::get<2>(dh_values);
  std::vector<unsigned char> user_public_value_data;
  user_public_value_s.serialize(user_public_value_data);
  this->network_driver->send(user_public_value_data);

  // 2) Receive m = (g^a, g^b) signed by the server
  std::vector<unsigned char> server_public_value_data =
      this->network_driver->read();
  ServerToUser_DHPublicValue_Message server_public_value_s;
  server_public_value_s.deserialize(server_public_value_data);

  // Verify signature
  bool verified = this->crypto_driver->DSA_verify(
      verification_key,
      concat_byteblocks(server_public_value_s.server_public_value,
                        server_public_value_s.user_public_value),
      server_public_value_s.server_signature);
  if (!verified) {
    this->cli_driver->print_warning("Signature verification failed");
    throw std::runtime_error("Voter: failed to verify server signature.");
  }
  if (server_public_value_s.user_public_value != std::get<2>(dh_values)) {
    this->cli_driver->print_warning("Session validation failed");
    throw std::runtime_error(
        "Voter: inconsistencies in voter public DH value.");
  }

  // Recover g^ab
  CryptoPP::SecByteBlock DH_shared_key = crypto_driver->DH_generate_shared_key(
      std::get<0>(dh_values), std::get<1>(dh_values),
      server_public_value_s.server_public_value);
  CryptoPP::SecByteBlock AES_key =
      crypto_driver->AES_generate_key(DH_shared_key);
  CryptoPP::SecByteBlock HMAC_key =
      crypto_driver->HMAC_generate_key(DH_shared_key);
  return std::make_pair(AES_key, HMAC_key);
}

/**
 * Handle registering with the registrar. This function:
 * 1) Generates and saves a DSA keypair, then handles key exchange.
 * 2) Sends our registration information.
 * 3) Receives and saves the certificate from the server.
 */
void VoterClient::HandleRegister(std::string input) {
  // Parse input and connect to registrar
  std::vector<std::string> args = string_split(input, ' ');
  if (args.size() != 3) {
    this->cli_driver->print_warning("usage: register <address> <port>");
    return;
  }
  this->network_driver->connect(args[1], std::stoi(args[2]));

  // // TODO: implement me!

  // generate dsa keys and save private key 
  std::pair<DSA::PrivateKey, DSA::PublicKey> dsa_keys = this->crypto_driver->DSA_generate_keys();
  this->DSA_voter_signing_key = dsa_keys.first;
  this->DSA_voter_verification_key = dsa_keys.second;

  SaveDSAPrivateKey(voter_config.voter_signing_key_path, this->DSA_voter_signing_key);

  // handle key exchange with registrar
  std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock> keys = this->HandleKeyExchange(this->DSA_registrar_verification_key);

  // send registration information
  VoterToRegistrar_Register_Message registration_msg;
  registration_msg.id = this->voter_config.voter_id;
  registration_msg.user_verification_key = this->DSA_voter_verification_key;

  std::vector<unsigned char> encrypted_registration_msg = 
    this->crypto_driver->encrypt_and_tag(keys.first, keys.second, &registration_msg);
  this->network_driver->send(encrypted_registration_msg);

  // RegistrarToVoter_Certificate_Message
  RegistrarToVoter_Certificate_Message certificate_msg;
  std::vector<unsigned char> certificate_cipher = this->network_driver->read();

  std::pair<std::vector<unsigned char>, bool> verified_certificate = 
    this->crypto_driver->decrypt_and_verify(keys.first, keys.second, certificate_cipher);

  if (!(verified_certificate.second)) {
    throw std::runtime_error("Unverified certificate provided by registrar");
    return;
  }

  certificate_msg.deserialize(verified_certificate.first);
  this->certificate = certificate_msg;
  SaveCertificate(voter_config.voter_certificate_path, this->certificate);
  this->network_driver->disconnect();
}

/**
 * Handle voting with the tallyer. This function:
 * 1) Handles key exchange.
 * 2) Generates a vote and zkp.
 * 3) Signs the vote and sends it to the tallyer
 */
void VoterClient::HandleVote(std::string input) {
  // Parse input and connect to tallyer
  std::vector<std::string> args = string_split(input, ' ');
  if ((args.size() - 3) != this->num_candidates) {
    this->cli_driver->print_warning("Must vote for exactly " + std::to_string(this->num_candidates) + " candidates");
  }
  this->network_driver->connect(args[1], std::stoi(args[2]));

  // TODO: implement me!

  // handle key exchange
  std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock> keys = 
    this->HandleKeyExchange(this->DSA_tallyer_verification_key);

  // generate a vote
  int num_votes = 0;
  std::vector<CryptoPP::Integer> vote_nums;
  for (int i=3; i<args.size(); i++) {
    if (args[i] == "1") {
      vote_nums.push_back(CryptoPP::Integer::One());
      num_votes += 1;
    } else if (args[i] == "0") {
      vote_nums.push_back(CryptoPP::Integer::Zero());
    } else {
      this->cli_driver->print_warning("vote can only be 0 or 1");
      return;
    }
  }

  // votes + zkps for each vote
  std::tuple<Votes_Struct, VoteZKPs_Struct, CryptoPP::Integer> votes =
    ElectionClient::GenerateVotes(vote_nums, this->EG_arbiter_public_key);
  
  // vote count zkps
  Votes_Struct votes_struct = std::get<0>(votes);
  VoteZKPs_Struct zkps_struct = std::get<1>(votes);
  CryptoPP::Integer r = std::get<2>(votes);

  std::pair<Vote_Struct, Count_ZKPs_Struct> count_zkps =
    ElectionClient::GenerateCountZKPs(votes_struct.votes, num_votes, this->k, r, this->EG_arbiter_public_key);
  
  VoterToTallyer_Vote_Message voter_to_tallyer_msg;
  voter_to_tallyer_msg.cert = this->certificate;
  voter_to_tallyer_msg.votes = votes_struct;
  voter_to_tallyer_msg.zkps = zkps_struct;

  voter_to_tallyer_msg.vote_count = count_zkps.first;
  voter_to_tallyer_msg.count_zkps = count_zkps.second;

  std::vector<unsigned char> vote_info_str = 
    concat_votes_and_zkps(votes_struct, zkps_struct, count_zkps.first, count_zkps.second); 

  voter_to_tallyer_msg.voter_signature = 
    this->crypto_driver->DSA_sign(this->DSA_voter_signing_key, vote_info_str);

  std::vector<unsigned char> encrypted_voter_to_tallyer_msg = 
    this->crypto_driver->encrypt_and_tag(keys.first, keys.second, &voter_to_tallyer_msg);
  this->network_driver->send(encrypted_voter_to_tallyer_msg);

  this->network_driver->disconnect();
}

/**
 * Handle verifying the results of the election.
 */
void VoterClient::HandleVerify(std::string input) {
  // Verify
  auto result = this->DoVerify();

  // Error if election failed
  if (!std::get<2>(result)) {
    this->cli_driver->print_warning("Election failed!");
    throw std::runtime_error("Election failed!");
  }

  // Print results
  std::vector<CryptoPP::Integer> zeros = std::get<0>(result);
  std::vector<CryptoPP::Integer> ones = std::get<1>(result);
  for (int i=0; i<this->num_candidates; i++) {
    this->cli_driver->print_success("Election succeeded!");
    std::string candidate = "Candidate " + std::to_string(i) + ": ";
    this->cli_driver->print_success(candidate);
    this->cli_driver->print_success("Number of votes for 0: " +
                                    CryptoPP::IntToString(zeros[i]));
    this->cli_driver->print_success("Number of votes for 1: " +
                                    CryptoPP::IntToString(ones[i]));
  }
}

/**
 * Handle verifying the results of the election. This function
 * 1) Verifies all vote ZKPs
 * 2) Verifies all partial decryption
 * 3) Combines the partial decryptions to retrieve the final result
 * 4) Returns a tuple of <0-votes, 1-votes, success>
 * If a vote is invalid, don't include it in the final combined vote or
 * throw an error either.
 */
std::tuple<std::vector<CryptoPP::Integer>, std::vector<CryptoPP::Integer>, bool> VoterClient::DoVerify() {
  // TODO: implement me!

  std::vector<VoteRow> votes = this->db_driver->all_votes();
  std::vector<VoteRow> valid_votes;

  for (int i=0; i<votes.size(); i++) {
    std::pair<Votes_Struct, VoteZKPs_Struct> vote = std::make_pair(votes[i].votes, votes[i].zkps);
    if (!(ElectionClient::VerifyVoteZKPs(vote, this->EG_arbiter_public_key))) {
      continue;
    }

    std::pair<Vote_Struct, Count_ZKPs_Struct> vote_count = std::make_pair(votes[i].vote_count, votes[i].count_zkps);
    if (!(ElectionClient::VerifyCountZKPs(vote_count, this->EG_arbiter_public_key))) {
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

  bool success = true;
  std::vector<PartialDecryptionRow> partial_dec_rows = this->db_driver->all_partial_decryptions();

  for (int i=0; i<partial_dec_rows.size(); i++) {
    PartialDecryptionRow row = partial_dec_rows[i];
    CryptoPP::Integer pki;
    LoadInteger(row.arbiter_vk_path, &pki);
    if (!(ElectionClient::VerifyPartialDecryptZKPs(row, pki))) {
      success = false;
      break;
    }
  }

  std::vector<CryptoPP::Integer> zeros;

  std::vector<CryptoPP::Integer> ones = ElectionClient::CombineResults(combined_votes, partial_dec_rows);
  for (int i=0; i<ones.size(); i++) {
    CryptoPP::Integer num_zeros(valid_votes.size() - ones[i]);
    zeros.push_back(num_zeros);
  }

  return std::make_tuple(zeros, ones, success);
}
