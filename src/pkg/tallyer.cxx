#include "../../include/pkg/tallyer.hpp"
#include "../../include/pkg/election.hpp"
#include "../../include-shared/keyloaders.hpp"
#include "../../include-shared/logger.hpp"
#include "constants.hpp"
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
TallyerClient::TallyerClient(TallyerConfig tallyer_config,
                             CommonConfig common_config) {
  // Make shared variables.
  this->tallyer_config = tallyer_config;
  this->common_config = common_config;
  this->num_candidates = std::stoi(common_config.num_candidates);
  this->k = std::stoi(common_config.k);
  this->cli_driver = std::make_shared<CLIDriver>();
  this->db_driver = std::make_shared<DBDriver>();
  this->db_driver->open(this->common_config.db_path);
  this->db_driver->init_tables();
  this->cli_driver->init();

  // Load tallyer keys.
  try {
    LoadDSAPrivateKey(tallyer_config.tallyer_signing_key_path,
                      this->DSA_tallyer_signing_key);
    LoadDSAPublicKey(common_config.tallyer_verification_key_path,
                     this->DSA_tallyer_verification_key);
  } catch (CryptoPP::FileStore::OpenErr) {
    this->cli_driver->print_warning(
        "Could not find tallyer keys, generating them instead.");
    CryptoDriver crypto_driver;
    auto keys = crypto_driver.DSA_generate_keys();
    this->DSA_tallyer_signing_key = keys.first;
    this->DSA_tallyer_verification_key = keys.second;
    SaveDSAPrivateKey(tallyer_config.tallyer_signing_key_path,
                      this->DSA_tallyer_signing_key);
    SaveDSAPublicKey(common_config.tallyer_verification_key_path,
                     this->DSA_tallyer_verification_key);
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
}

/**
 * Run server.
 */
void TallyerClient::run(int port) {

  // Start listener thread
  std::thread listener_thread(&TallyerClient::ListenForConnections, this, port);
  listener_thread.detach();

  // Wait for a sign to exit.
  std::string message;
  this->cli_driver->print_info("enter \"exit\" to exit");
  while (std::getline(std::cin, message)) {
    if (message == "exit") {
      this->db_driver->close();
      return;
    }
  }
}

/**
 * Listen for new connections.
 */
void TallyerClient::ListenForConnections(int port) {
  while (1) {
    // Create new network driver and crypto driver for this connection
    std::shared_ptr<NetworkDriver> network_driver =
        std::make_shared<NetworkDriverImpl>();
    std::shared_ptr<CryptoDriver> crypto_driver =
        std::make_shared<CryptoDriver>();
    network_driver->listen(port);
    std::thread connection_thread(&TallyerClient::HandleTally, this,
                                  network_driver, crypto_driver);
    connection_thread.detach();
  }
}

/**
 * Handle key exchange with voter
 */
std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock>
TallyerClient::HandleKeyExchange(std::shared_ptr<NetworkDriver> network_driver,
                                 std::shared_ptr<CryptoDriver> crypto_driver) {
  // Generate private/public DH keys
  auto dh_values = crypto_driver->DH_initialize();

  // Listen for g^a
  std::vector<unsigned char> user_public_value = network_driver->read();
  UserToServer_DHPublicValue_Message user_public_value_s;
  user_public_value_s.deserialize(user_public_value);

  // Respond with m = (g^b, g^a) signed with our private DSA key
  ServerToUser_DHPublicValue_Message public_value_s;
  public_value_s.server_public_value = std::get<2>(dh_values);
  public_value_s.user_public_value = user_public_value_s.public_value;
  public_value_s.server_signature = crypto_driver->DSA_sign(
      this->DSA_tallyer_signing_key,
      concat_byteblocks(public_value_s.server_public_value,
                        public_value_s.user_public_value));

  // Sign and send message
  std::vector<unsigned char> message_bytes;
  public_value_s.serialize(message_bytes);
  network_driver->send(message_bytes);

  // Recover g^ab
  CryptoPP::SecByteBlock DH_shared_key = crypto_driver->DH_generate_shared_key(
      std::get<0>(dh_values), std::get<1>(dh_values),
      user_public_value_s.public_value);
  CryptoPP::SecByteBlock AES_key =
      crypto_driver->AES_generate_key(DH_shared_key);
  CryptoPP::SecByteBlock HMAC_key =
      crypto_driver->HMAC_generate_key(DH_shared_key);
  return std::make_pair(AES_key, HMAC_key);
}

/**
 * Handle tallying a new vote. This function:
 * 1) Handles key exchange.
 * 2) Receives a vote from the user, makes sure the user hasn't voted yet,
 *    verifies its certificate, the voter signature, and the zkp.
 * 3) Signs the vote and publishes it to the database if it is valid.
 * 4) Mark this user as having already voted.
 * Disconnect and throw an error if any MACs, certs, or zkps are invalid
 * or if the user has already voted.
 */
void TallyerClient::HandleTally(std::shared_ptr<NetworkDriver> network_driver,
                                std::shared_ptr<CryptoDriver> crypto_driver) {
  // TODO: implement me!

  // // key exchange
  std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock> keys = 
    this->HandleKeyExchange(network_driver, crypto_driver);
  
  // get VoterToTallyer_Vote_Message
  std::vector<unsigned char> raw_voter_to_tallyer = network_driver->read();
  std::pair<std::vector<unsigned char>, bool> voter_to_tallyer_cipher = 
    crypto_driver->decrypt_and_verify(keys.first, keys.second, raw_voter_to_tallyer);

  if (!(voter_to_tallyer_cipher.second)) {
    throw std::runtime_error("Unverified voter to tallyer message sent");
    network_driver->disconnect();
    return;
  }

  VoterToTallyer_Vote_Message voter_to_tallyer_msg;
  voter_to_tallyer_msg.deserialize(voter_to_tallyer_cipher.first);

  // check that the user has not voted
  if (this->db_driver->voter_voted(voter_to_tallyer_msg.cert.id)) {
    throw std::runtime_error("Voter has previously voted");
    network_driver->disconnect();
    return;
  }

  // verify the certificate from the registrar
  std::vector<unsigned char> id_plus_vk = 
    concat_string_and_dsakey(voter_to_tallyer_msg.cert.id, voter_to_tallyer_msg.cert.verification_key);
  if (!(crypto_driver->DSA_verify(this->DSA_registrar_verification_key, id_plus_vk, voter_to_tallyer_msg.cert.registrar_signature))) {
    throw std::runtime_error("Invalid registrar certificate provided by voter");
    network_driver->disconnect();
    return;
  }

  //verify the voter's signature
  std::vector<unsigned char> vote_info_str = 
    concat_votes_and_zkps(voter_to_tallyer_msg.votes, voter_to_tallyer_msg.zkps, 
                          voter_to_tallyer_msg.vote_count, voter_to_tallyer_msg.count_zkps);

  if (!(crypto_driver->DSA_verify(voter_to_tallyer_msg.cert.verification_key, vote_info_str, voter_to_tallyer_msg.voter_signature))) {
    throw std::runtime_error("Invalid voter signature provided in voter to tallyer message");
    network_driver->disconnect();
    return;
  }

  // check zkps for each vote
  std::pair<Votes_Struct, VoteZKPs_Struct> votes = 
    std::make_pair(voter_to_tallyer_msg.votes, voter_to_tallyer_msg.zkps);
  if (!(ElectionClient::VerifyVoteZKPs(votes, this->EG_arbiter_public_key))) {
    throw std::runtime_error("Invalid zkp provided by voter");
    network_driver->disconnect();
    return;
  }

  for (auto &vote_struct : voter_to_tallyer_msg.votes.votes) {
    std::cout << "Sample a: " << std::endl;
    std::cout << vote_struct.a << std::endl;
  }

  // check zkps for vote count
  std::pair<Vote_Struct, Count_ZKPs_Struct> vote_count = 
    std::make_pair(voter_to_tallyer_msg.vote_count, voter_to_tallyer_msg.count_zkps);
  if (!(ElectionClient::VerifyCountZKPs(vote_count, this->EG_arbiter_public_key))) {
    throw std::runtime_error("Invalid count zkp provided by voter");
    network_driver->disconnect();
    return;
  }

  // create a TallyerToWorld_Vote_Message, add the votes to the database, and mark the voter as having voted
  TallyerToWorld_Vote_Message vote_row;
  vote_row.votes = voter_to_tallyer_msg.votes;
  vote_row.zkps = voter_to_tallyer_msg.zkps;
  vote_row.vote_count = voter_to_tallyer_msg.vote_count;
  vote_row.count_zkps = voter_to_tallyer_msg.count_zkps;
  vote_row.tallyer_signature = crypto_driver->DSA_sign(this->DSA_tallyer_signing_key, vote_info_str);

  this->db_driver->insert_vote(vote_row);
  this->db_driver->insert_voted(voter_to_tallyer_msg.cert.id);
}
