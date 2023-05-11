#include "../../include/pkg/registrar.hpp"
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
RegistrarClient::RegistrarClient(RegistrarConfig registrar_config,
                                 CommonConfig common_config) {
  // Make shared variables.
  this->registrar_config = registrar_config;
  this->common_config = common_config;
  this->k = common_config.candidates.size();
  this->cli_driver = std::make_shared<CLIDriver>();
  this->db_driver = std::make_shared<DBDriver>();
  this->db_driver->open(this->common_config.db_path);
  this->db_driver->init_tables();
  this->cli_driver->init();

  // Load registrar keys.
  try {
    LoadDSAPrivateKey(registrar_config.registrar_signing_key_path,
                      this->DSA_registrar_signing_key);
    LoadDSAPublicKey(common_config.registrar_verification_key_path,
                     this->DSA_registrar_verification_key);
  } catch (CryptoPP::FileStore::OpenErr) {
    this->cli_driver->print_warning(
        "Could not find registrar keys, generating them instead.");
    CryptoDriver crypto_driver;
    auto keys = crypto_driver.DSA_generate_keys();
    this->DSA_registrar_signing_key = keys.first;
    this->DSA_registrar_verification_key = keys.second;
    SaveDSAPrivateKey(registrar_config.registrar_signing_key_path,
                      this->DSA_registrar_signing_key);
    SaveDSAPublicKey(common_config.registrar_verification_key_path,
                     this->DSA_registrar_verification_key);
  }

  // Load election public key
  try {
    LoadElectionPublicKey(common_config.arbiter_public_key_paths,
                          &this->EG_arbiter_public_key);
  } catch (CryptoPP::FileStore::OpenErr) {
    this->cli_driver->print_warning("Error loading arbiter public keys; "
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

void RegistrarClient::run(int port) {
  // Start listener thread
  std::thread listener_thread(&RegistrarClient::ListenForConnections, this,
                              port);
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
 * Listen for new connections
 */
void RegistrarClient::ListenForConnections(int port) {
  while (1) {
    // Create new network driver and crypto driver for this connection
    std::shared_ptr<NetworkDriver> network_driver =
        std::make_shared<NetworkDriverImpl>();
    std::shared_ptr<CryptoDriver> crypto_driver =
        std::make_shared<CryptoDriver>();
    network_driver->listen(port);
    std::thread connection_thread(&RegistrarClient::HandleRegister, this,
                                  network_driver, crypto_driver);
    connection_thread.detach();
  }
}

/**
 * Handle key exchange with voter
 */
std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock>
RegistrarClient::HandleKeyExchange(
    std::shared_ptr<NetworkDriver> network_driver,
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
      this->DSA_registrar_signing_key,
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
 * Handle new registration. This function:
 * 1) Handles key exchange.
 * 2) Gets user info and verifies that the user hasn't already registered.
 *    (if already registered, return existing certificate).
 * 3) Constructs and sends a certificate to the user.
 * 4) Adds the user to the database and disconnects.
 * Disconnect and throw an error if any MACs are invalid.
 */
void RegistrarClient::HandleRegister(
    std::shared_ptr<NetworkDriver> network_driver,
    std::shared_ptr<CryptoDriver> crypto_driver) {
  // TODO: implement me!

  // handle key exchange with voter
  std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock> keys = this->HandleKeyExchange(network_driver, crypto_driver);

  // get the VoterToRegistrar_Register_Message
  VoterToRegistrar_Register_Message voter_register_msg;
  std::vector<unsigned char> voter_register_msg_raw = network_driver->read();
  std::pair<std::vector<unsigned char>, bool> decrypted_voter_register_msg_raw = 
    crypto_driver->decrypt_and_verify(keys.first, keys.second, voter_register_msg_raw);
  if (!(decrypted_voter_register_msg_raw.second)) {
    throw std::runtime_error("Unverified voter to registrar registration msg");
  }
  voter_register_msg.deserialize(decrypted_voter_register_msg_raw.first);

  // if the user's certificate has already been stored, return it
  RegistrarToVoter_Certificate_Message voter_row = this->db_driver->find_voter(voter_register_msg.id);
  if (voter_row.id != "") {
    std::vector<unsigned char> encrypted_cert = crypto_driver->encrypt_and_tag(keys.first, keys.second, &voter_row);
    network_driver->send(encrypted_cert);
    network_driver->disconnect();
    return;
  }

  // otherwise, populate the voter row and insert the voter into the database
  voter_row.id = voter_register_msg.id;
  voter_row.verification_key = voter_register_msg.user_verification_key;

  std::vector<unsigned char> id_plus_vk = concat_string_and_dsakey(voter_row.id, voter_row.verification_key);
  voter_row.registrar_signature = crypto_driver->DSA_sign(this->DSA_registrar_signing_key, id_plus_vk);

  this->db_driver->insert_voter(voter_row);

  // encrypt certificate and send to the voter
  std::vector<unsigned char> encrypted_cert = crypto_driver->encrypt_and_tag(keys.first, keys.second, &voter_row);
  network_driver->send(encrypted_cert);
  network_driver->disconnect();
}
