#include "../include-shared/messages.hpp"
#include "../include-shared/util.hpp"

// ================================================
// MESSAGE TYPES
// ================================================

/**
 * Get message type.
 */
MessageType::T get_message_type(std::vector<unsigned char> &data) {
  return (MessageType::T)data[0];
}

// ================================================
// SERIALIZERS
// ================================================

/**
 * Puts the bool b into the end of data.
 */
int put_bool(bool b, std::vector<unsigned char> &data) {
  data.push_back((char)b);
  return 1;
}

/**
 * Puts the string s into the end of data.
 */
int put_string(std::string s, std::vector<unsigned char> &data) {
  // Put length
  int idx = data.size();
  data.resize(idx + sizeof(size_t));
  size_t str_size = s.size();
  std::memcpy(&data[idx], &str_size, sizeof(size_t));

  // Put string
  data.insert(data.end(), s.begin(), s.end());
  return data.size() - idx;
}

/**
 * Puts the integer i into the end of data.
 */
int put_integer(CryptoPP::Integer i, std::vector<unsigned char> &data) {
  return put_string(CryptoPP::IntToString(i), data);
}

/**
 * Adds a size param to the end of data.
*/
void add_size_param(std::vector<unsigned char> &data, size_t &size_param) {
  int idx = data.size();
  data.resize(idx + sizeof(size_t));
  std::memcpy(&data[idx], &size_param, sizeof(size_t));
}

/**
 * Puts the nest bool from data at index idx into b.
 */
int get_bool(bool *b, std::vector<unsigned char> &data, int idx) {
  *b = (bool)data[idx];
  return 1;
}

/**
 * Puts the nest string from data at index idx into s.
 */
int get_string(std::string *s, std::vector<unsigned char> &data, int idx) {
  // Get length
  size_t str_size;
  std::memcpy(&str_size, &data[idx], sizeof(size_t));

  // Get string
  std::vector<unsigned char> svec(&data[idx + sizeof(size_t)],
                                  &data[idx + sizeof(size_t) + str_size]);
  *s = chvec2str(svec);
  return sizeof(size_t) + str_size;
}

/**
 * Puts the next integer from data at index idx into i.
 */
int get_integer(CryptoPP::Integer *i, std::vector<unsigned char> &data,
                int idx) {
  std::string i_str;
  int n = get_string(&i_str, data, idx);
  *i = CryptoPP::Integer(i_str.c_str());
  return n;
}

// ================================================
// WRAPPERS
// ================================================

/**
 * serialize HMACTagged_Wrapper.
 */
void HMACTagged_Wrapper::serialize(std::vector<unsigned char> &data) {
  // Add message type.
  data.push_back((char)MessageType::HMACTagged_Wrapper);

  // Add fields.
  put_string(chvec2str(this->payload), data);

  std::string iv = byteblock_to_string(this->iv);
  put_string(iv, data);

  put_string(this->mac, data);
}

/**
 * deserialize HMACTagged_Wrapper.
 */
int HMACTagged_Wrapper::deserialize(std::vector<unsigned char> &data) {
  // Check correct message type.
  assert(data[0] == MessageType::HMACTagged_Wrapper);

  // Get fields.
  std::string payload_string;
  int n = 1;
  n += get_string(&payload_string, data, n);
  this->payload = str2chvec(payload_string);

  std::string iv;
  n += get_string(&iv, data, n);
  this->iv = string_to_byteblock(iv);

  n += get_string(&this->mac, data, n);
  return n;
}

// ================================================
// KEY EXCHANGE
// ================================================

/**
 * serialize UserToServer_DHPublicValue_Message.
 */
void UserToServer_DHPublicValue_Message::serialize(
    std::vector<unsigned char> &data) {
  // Add message type.
  data.push_back((char)MessageType::UserToServer_DHPublicValue_Message);

  // Add fields.
  std::string public_string = byteblock_to_string(this->public_value);
  put_string(public_string, data);
}

/**
 * deserialize UserToServer_DHPublicValue_Message.
 */
int UserToServer_DHPublicValue_Message::deserialize(
    std::vector<unsigned char> &data) {
  // Check correct message type.
  assert(data[0] == MessageType::UserToServer_DHPublicValue_Message);

  // Get fields.
  std::string public_string;
  int n = 1;
  n += get_string(&public_string, data, n);
  this->public_value = string_to_byteblock(public_string);
  return n;
}

/**
 * serialize ServerToUser_DHPublicValue_Message.
 */
void ServerToUser_DHPublicValue_Message::serialize(
    std::vector<unsigned char> &data) {
  // Add message type.
  data.push_back((char)MessageType::ServerToUser_DHPublicValue_Message);

  // Add fields.
  std::string server_public_string =
      byteblock_to_string(this->server_public_value);
  std::string user_public_string =
      byteblock_to_string(this->user_public_value);
  put_string(server_public_string, data);
  put_string(user_public_string, data);
  put_string(this->server_signature, data);
}

/**
 * deserialize ServerToUser_DHPublicValue_Message.
 */
int ServerToUser_DHPublicValue_Message::deserialize(
    std::vector<unsigned char> &data) {
  // Check correct message type.
  assert(data[0] == MessageType::ServerToUser_DHPublicValue_Message);

  // Get fields.
  std::string server_public_string;
  std::string user_public_string;
  int n = 1;
  n += get_string(&server_public_string, data, n);
  n += get_string(&user_public_string, data, n);
  n += get_string(&this->server_signature, data, n);
  this->server_public_value = string_to_byteblock(server_public_string);
  this->user_public_value = string_to_byteblock(user_public_string);
  return n;
}

// ================================================
// VOTER <==> REGISTRAR
// ================================================

/**
 * serialize VoterToRegistrar_Register_Message.
 */
void VoterToRegistrar_Register_Message::serialize(
    std::vector<unsigned char> &data) {
  // Add message type.
  data.push_back((char)MessageType::VoterToRegistrar_Register_Message);

  // Serialize signing key.
  std::string user_verification_key_str;
  CryptoPP::StringSink ss(user_verification_key_str);
  this->user_verification_key.Save(ss);

  // Add fields.
  put_string(this->id, data);
  put_string(user_verification_key_str, data);
}

/**
 * deserialize VoterToRegistrar_Register_Message.
 */
int VoterToRegistrar_Register_Message::deserialize(
    std::vector<unsigned char> &data) {
  // Check correct message type.
  assert(data[0] == MessageType::VoterToRegistrar_Register_Message);

  // Get fields.
  std::string user_verification_key_str;
  int n = 1;
  n += get_string(&this->id, data, n);
  n += get_string(&user_verification_key_str, data, n);

  // Deserialize signing key.
  CryptoPP::StringSource ss(user_verification_key_str, true);
  this->user_verification_key.Load(ss);
  return n;
}

/**
 * serialize RegistrarToVoter_Certificate_Message.
 */
void RegistrarToVoter_Certificate_Message::serialize(
    std::vector<unsigned char> &data) {
  // Add message type.
  data.push_back((char)MessageType::RegistrarToVoter_Certificate_Message);

  // Serialize signing key.
  std::string verification_key_str;
  CryptoPP::StringSink ss(verification_key_str);
  this->verification_key.Save(ss);

  // Add fields.
  put_string(this->id, data);
  put_string(verification_key_str, data);
  put_string(this->registrar_signature, data);
}

/**
 * deserialize RegistrarToVoter_Certificate_Message.
 */
int RegistrarToVoter_Certificate_Message::deserialize(
    std::vector<unsigned char> &data) {
  // Check correct message type.
  assert(data[0] == MessageType::RegistrarToVoter_Certificate_Message);

  // Get fields.
  std::string verification_key_str;
  int n = 1;
  n += get_string(&this->id, data, n);
  n += get_string(&verification_key_str, data, n);
  n += get_string(&this->registrar_signature, data, n);

  // Deserialize signing key.
  CryptoPP::StringSource ss(verification_key_str, true);
  this->verification_key.Load(ss);
  return n;
}

// ================================================
// VOTER <==> TALLYER
// ================================================

/**
 * serialize Vote_Struct.
 */
void Vote_Struct::serialize(std::vector<unsigned char> &data) {
  // Add message type.
  data.push_back((char)MessageType::Vote_Struct);

  // Add fields.
  put_integer(this->a, data);
  put_integer(this->b, data);
}

/**
 * deserialize Vote_Struct.
 */
int Vote_Struct::deserialize(std::vector<unsigned char> &data) {
  // Check correct message type.
  assert(data[0] == MessageType::Vote_Struct);

  // Get fields.
  int n = 1;
  n += get_integer(&this->a, data, n);
  n += get_integer(&this->b, data, n);
  return n;
}

/**
 * serialize Votes_Struct.
 */
void Votes_Struct::serialize(std::vector<unsigned char> &data) {
  // Add message type.
  data.push_back((char)MessageType::Votes_Struct);

  size_t num_votes = this->votes.size();
  add_size_param(data, num_votes);

  for (auto &vote : this->votes) {
    std::vector<unsigned char> vote_data;
    vote.serialize(vote_data);
    data.insert(data.end(), vote_data.begin(), vote_data.end());
  }
}

/**
 * deserialize Votes_Struct.
 */
int Votes_Struct::deserialize(std::vector<unsigned char> &data) {
  // Check correct message type.
  assert(data[0] == MessageType::Votes_Struct);

  int n = 1;

  // Get fields.
  size_t num_votes;
  std::memcpy(&num_votes, &data[n], sizeof(size_t));
  n += sizeof(size_t);

  std::vector<Vote_Struct> votes;
  for (int i=0; i<num_votes; i++) {
    Vote_Struct vote;
    std::vector<unsigned char> vote_data = 
      std::vector<unsigned char>(data.begin() + n, data.end());
    
    n += vote.deserialize(vote_data);
    votes.push_back(vote);
  }
  this->votes = votes;

  return n;
}


/**
 * serialize VoteZKP_Struct.
 */
void VoteZKP_Struct::serialize(std::vector<unsigned char> &data) {
  // Add message type.
  data.push_back((char)MessageType::VoteZKP_Struct);

  // Add fields.
  put_integer(this->a0, data);
  put_integer(this->a1, data);
  put_integer(this->b0, data);
  put_integer(this->b1, data);
  put_integer(this->c0, data);
  put_integer(this->c1, data);
  put_integer(this->r0, data);
  put_integer(this->r1, data);
}

/**
 * deserialize VoteZKP_Struct.
 */
int VoteZKP_Struct::deserialize(std::vector<unsigned char> &data) {
  // Check correct message type.
  assert(data[0] == MessageType::VoteZKP_Struct);

  // Get fields.
  int n = 1;
  n += get_integer(&this->a0, data, n);
  n += get_integer(&this->a1, data, n);
  n += get_integer(&this->b0, data, n);
  n += get_integer(&this->b1, data, n);
  n += get_integer(&this->c0, data, n);
  n += get_integer(&this->c1, data, n);
  n += get_integer(&this->r0, data, n);
  n += get_integer(&this->r1, data, n);
  return n;
}

/**
 * serialize VoteZKPs_Struct.
 */
void VoteZKPs_Struct::serialize(std::vector<unsigned char> &data) {
  // Add message type.
  data.push_back((char)MessageType::VoteZKPs_Struct);

  // Add fields.
  size_t num_zkps = this->zkps.size();
  add_size_param(data, num_zkps);

  for (auto &zkp: this->zkps) {
    std::vector<unsigned char> zkp_data;
    zkp.serialize(zkp_data);
    data.insert(data.end(), zkp_data.begin(), zkp_data.end());
  }
}

/**
 * deserialize VoteZKPs_Struct.
 */
int VoteZKPs_Struct::deserialize(std::vector<unsigned char> &data) {
  // Check correct message type.
  assert(data[0] == MessageType::VoteZKPs_Struct);

  // Get fields.
  int n = 1;

  size_t num_zkps;
  std::memcpy(&num_zkps, &data[n], sizeof(size_t));
  n += sizeof(size_t);

  std::vector<VoteZKP_Struct> zkps;
  for (int i=0; i<num_zkps; i++) {
    VoteZKP_Struct zkp;
    std::vector<unsigned char> zkp_data =
      std::vector<unsigned char>(data.begin() + n, data.end());
    
    n += zkp.deserialize(zkp_data);
    zkps.push_back(zkp);
  }
  this->zkps = zkps;

  return n;
}

void Count_ZKP_Struct::serialize(std::vector<unsigned char> &data) {
  data.push_back((char)MessageType::Count_ZKP_Struct);

  put_integer(this->a_i, data);
  put_integer(this->b_i, data);
  put_integer(this->c_i, data);
  put_integer(this->r_i, data);
}

int Count_ZKP_Struct::deserialize(std::vector<unsigned char> &data) {
  assert(data[0] == MessageType::Count_ZKP_Struct);

  int n = 1;
  n += get_integer(&this->a_i, data, n);
  n += get_integer(&this->b_i, data, n);
  n += get_integer(&this->c_i, data, n);
  n += get_integer(&this->r_i, data, n);
  return n;
}

void Count_ZKPs_Struct::serialize(std::vector<unsigned char> &data) {
  data.push_back((char)MessageType::Count_ZKPs_Struct);

  size_t num_count_zkps = this->count_zkps.size();
  add_size_param(data, num_count_zkps);

  for (auto &count_zkp : this->count_zkps) {
    std::vector<unsigned char> zkp_data;
    count_zkp.serialize(zkp_data);
    data.insert(data.end(), zkp_data.begin(), zkp_data.end());
  }
}

int Count_ZKPs_Struct::deserialize(std::vector<unsigned char> &data) {
  assert(data[0] == MessageType::Count_ZKPs_Struct);

  int n = 1;

  size_t num_count_zkps;
  std::memcpy(&num_count_zkps, &data[n], sizeof(size_t));
  n += sizeof(size_t);

  std::vector<Count_ZKP_Struct> count_zkps;
  for (int i=0; i<num_count_zkps; i++) {
    Count_ZKP_Struct zkp;
    std::vector<unsigned char> zkp_data = 
      std::vector<unsigned char>(data.begin() + n, data.end());
    
    n += zkp.deserialize(zkp_data);
    count_zkps.push_back(zkp);
  }
  this->count_zkps = count_zkps;
  
  return n;
}

/**
 * serialize VoterToTallyer_Vote_Message.
 */
void VoterToTallyer_Vote_Message::serialize(std::vector<unsigned char> &data) {
  // Add message type.
  data.push_back((char)MessageType::VoterToTallyer_Vote_Message);

  // Add fields.
  std::vector<unsigned char> cert_data;
  this->cert.serialize(cert_data);
  data.insert(data.end(), cert_data.begin(), cert_data.end());

  std::vector<unsigned char> votes_data;
  this->votes.serialize(votes_data);
  data.insert(data.end(), votes_data.begin(), votes_data.end());

  std::vector<unsigned char> zkps_data;
  this->zkps.serialize(zkps_data);
  data.insert(data.end(), zkps_data.begin(), zkps_data.end());

  std::vector<unsigned char> vote_count_data;
  this->vote_count.serialize(vote_count_data);
  data.insert(data.end(), vote_count_data.begin(), vote_count_data.end());

  std::vector<unsigned char> count_zkps_data;
  this->count_zkps.serialize(count_zkps_data);
  data.insert(data.end(), count_zkps_data.begin(), count_zkps_data.end());
  
  put_string(this->voter_signature, data);
}

/**
 * deserialize VoterToTallyer_Vote_Message.
 */
int VoterToTallyer_Vote_Message::deserialize(std::vector<unsigned char> &data) {
  // Check correct message type.
  assert(data[0] == MessageType::VoterToTallyer_Vote_Message);

  // Get fields.
  int n = 1;

  std::vector<unsigned char> cert_data =
    std::vector<unsigned char>(data.begin() + n, data.end());
  n += this->cert.deserialize(cert_data);

  std::vector<unsigned char> votes_data = 
    std::vector<unsigned char>(data.begin() + n, data.end());
  n += this->votes.deserialize(votes_data);

  std::vector<unsigned char> zkps_data = 
    std::vector<unsigned char>(data.begin() + n, data.end());
  n += this->zkps.deserialize(zkps_data);

  std::vector<unsigned char> vote_count_data =
    std::vector<unsigned char>(data.begin() + n, data.end());
  n += this->vote_count.deserialize(vote_count_data);

  std::vector<unsigned char> count_zkps_data = 
    std::vector<unsigned char>(data.begin() + n, data.end());
  n += this->count_zkps.deserialize(count_zkps_data);

  n += get_string(&this->voter_signature, data, n);
  return n;
}

/**
 * serialize TallyerToWorld_Vote_Message.
 */
void TallyerToWorld_Vote_Message::serialize(std::vector<unsigned char> &data) {
  // Add message type.
  data.push_back((char)MessageType::TallyerToWorld_Vote_Message);

  // Add fields.
  std::vector<unsigned char> votes_data;
  this->votes.serialize(votes_data);
  data.insert(data.end(), votes_data.begin(), votes_data.end());

  std::vector<unsigned char> zkps_data;
  this->zkps.serialize(zkps_data);
  data.insert(data.end(), zkps_data.begin(), zkps_data.end());

  std::vector<unsigned char> vote_count_data;
  this->vote_count.serialize(vote_count_data);
  data.insert(data.end(), vote_count_data.begin(), vote_count_data.end());

  std::vector<unsigned char> count_zkps_data;
  this->count_zkps.serialize(count_zkps_data);
  data.insert(data.end(), count_zkps_data.begin(), count_zkps_data.end());

  put_string(this->tallyer_signature, data);
}

/**
 * deserialize TallyerToWorld_Vote_Message.
 */
int TallyerToWorld_Vote_Message::deserialize(std::vector<unsigned char> &data) {
  // Check correct message type.
  assert(data[0] == MessageType::TallyerToWorld_Vote_Message);

  // Get fields.
  int n = 1;
  std::vector<unsigned char> votes_data = 
    std::vector<unsigned char>(data.begin() + n, data.end());
  n += this->votes.deserialize(votes_data);

  std::vector<unsigned char> zkps_data = 
    std::vector<unsigned char>(data.begin() + n, data.end());
  n += this->zkps.deserialize(zkps_data);

  std::vector<unsigned char> vote_count_data =
    std::vector<unsigned char>(data.begin() + n, data.end());
  n += this->vote_count.deserialize(vote_count_data);

  std::vector<unsigned char> count_zkps_data = 
    std::vector<unsigned char>(data.begin() + n, data.end());
  n += this->count_zkps.deserialize(count_zkps_data);

  n += get_string(&this->tallyer_signature, data, n);
  return n;
}

// ================================================
// ARBITER <==> WORLD
// ================================================

/**
 * serialize PartialDecryption_Struct.
 */
void PartialDecryption_Struct::serialize(std::vector<unsigned char> &data) {
  // Add message type.
  data.push_back((char)MessageType::PartialDecryption_Struct);

  // Add fields.
  put_integer(this->d, data);
  std::vector<unsigned char> aggregate_ciphertext_data;
  this->aggregate_ciphertext.serialize(aggregate_ciphertext_data);
  data.insert(data.end(), aggregate_ciphertext_data.begin(),
              aggregate_ciphertext_data.end());
}

/**
 * deserialize PartialDecryption_Struct.
 */
int PartialDecryption_Struct::deserialize(std::vector<unsigned char> &data) {
  // Check correct message type.
  assert(data[0] == MessageType::PartialDecryption_Struct);

  // Get fields.
  int n = 1;
  n += get_integer(&this->d, data, n);
  std::vector<unsigned char> aggregate_ciphertext_slice =
      std::vector<unsigned char>(data.begin() + n, data.end());
  n += this->aggregate_ciphertext.deserialize(aggregate_ciphertext_slice);
  return n;
}

/**
 * serialize PartialDecryptions_Struct.
 */
void PartialDecryptions_Struct::serialize(std::vector<unsigned char> &data) {
  // Add message type.
  data.push_back((char)MessageType::PartialDecryptions_Struct);

  // Add fields.
  size_t num_decs = this->decs.size();
  add_size_param(data, num_decs);

  for (auto &dec : decs) {
    std::vector<unsigned char> dec_data;
    dec.serialize(dec_data);
    data.insert(data.end(), dec_data.begin(), dec_data.end());
  }
}

/**
 * deserialize PartialDecryptions_Struct.
 */
int PartialDecryptions_Struct::deserialize(std::vector<unsigned char> &data) {
  // Check correct message type.
  assert(data[0] == MessageType::PartialDecryptions_Struct);

  // Get fields.
  int n = 1;

  size_t num_decs;
  std::memcpy(&num_decs, &data[n], sizeof(size_t));
  n += sizeof(size_t);

  std::vector<PartialDecryption_Struct> decs;
  for (int i=0; i<num_decs; i++) {
    PartialDecryption_Struct dec;
    std::vector<unsigned char> dec_data = 
      std::vector<unsigned char>(data.begin() + n, data.end());
    
    n += dec.deserialize(dec_data);
    decs.push_back(dec);
  }
  this->decs = decs;

  return n;
}

/**
 * serialize DecryptionZKP_Struct.
 */
void DecryptionZKP_Struct::serialize(std::vector<unsigned char> &data) {
  // Add message type.
  data.push_back((char)MessageType::DecryptionZKP_Struct);

  // Add fields.
  put_integer(this->u, data);
  put_integer(this->v, data);
  put_integer(this->s, data);
}

/**
 * deserialize DecryptionZKP_Struct.
 */
int DecryptionZKP_Struct::deserialize(std::vector<unsigned char> &data) {
  // Check correct message type.
  assert(data[0] == MessageType::DecryptionZKP_Struct);

  // Get fields.
  int n = 1;
  n += get_integer(&this->u, data, n);
  n += get_integer(&this->v, data, n);
  n += get_integer(&this->s, data, n);
  return n;
}

/**
 * serialize DecryptionZKPs_Struct.
 */
void DecryptionZKPs_Struct::serialize(std::vector<unsigned char> &data) {
  // Add message type.
  data.push_back((char)MessageType::DecryptionZKPs_Struct);

  // Add fields.
  size_t num_zkps = this->zkps.size();
  add_size_param(data, num_zkps);

  for (auto &zkp : zkps) {
    std::vector<unsigned char> zkp_data;
    zkp.serialize(zkp_data);
    data.insert(data.end(), zkp_data.begin(), zkp_data.end());
  }
}

/**
 * deserialize DecryptionZKPs_Struct.
 */
int DecryptionZKPs_Struct::deserialize(std::vector<unsigned char> &data) {
  // Check correct message type.
  assert(data[0] == MessageType::DecryptionZKPs_Struct);

  // Get fields.
  int n = 1;

  size_t num_zkps;
  std::memcpy(&num_zkps, &data[n], sizeof(size_t));
  n += sizeof(size_t);

  std::vector<DecryptionZKP_Struct> zkps;
  for (int i=0; i<num_zkps; i++) {
    DecryptionZKP_Struct zkp;
    std::vector<unsigned char> zkp_data = 
      std::vector<unsigned char>(data.begin() + n, data.end());
    
    n += zkp.deserialize(zkp_data);
    zkps.push_back(zkp);
  }
  this->zkps = zkps;

  return n;
}

/**
 * serialize ArbiterToWorld_PartialDecryption_Message.
 */
void ArbiterToWorld_PartialDecryption_Message::serialize(
    std::vector<unsigned char> &data) {
  // Add message type.
  data.push_back((char)MessageType::ArbiterToWorld_PartialDecryption_Message);

  // Add fields.
  put_string(this->arbiter_id, data);

  put_string(this->arbiter_vk_path, data);

  std::vector<unsigned char> decs_data;
  this->decs.serialize(decs_data);
  data.insert(data.end(), decs_data.begin(), decs_data.end());

  std::vector<unsigned char> zkps_data;
  this->zkps.serialize(zkps_data);
  data.insert(data.end(), zkps_data.begin(), zkps_data.end());
}

/**
 * deserialize ArbiterToWorld_PartialDecryption_Message.
 */
int ArbiterToWorld_PartialDecryption_Message::deserialize(
    std::vector<unsigned char> &data) {
  // Check correct message type.
  assert(data[0] == MessageType::ArbiterToWorld_PartialDecryption_Message);

  // Get fields.
  int n = 1;
  n += get_string(&this->arbiter_id, data, n);

  n += get_string(&this->arbiter_vk_path, data, n);

  std::vector<unsigned char> decs_data = 
    std::vector<unsigned char>(data.begin() + n, data.end());
  n += this->decs.deserialize(decs_data);

  std::vector<unsigned char> zkps_data = 
    std::vector<unsigned char>(data.begin() + n, data.end());
  n += this->zkps.deserialize(zkps_data);

  return n;
}

// ================================================
// SIGNING HELPERS
// ================================================

/**
 * Concatenate a string and a DSA public key into vector of unsigned char
 */
std::vector<unsigned char>
concat_string_and_dsakey(std::string &s, CryptoPP::DSA::PublicKey &k) {
  // Concat s to vec
  std::vector<unsigned char> v;
  v.insert(v.end(), s.begin(), s.end());

  // Concat k to vec
  std::string k_str;
  CryptoPP::StringSink ss(k_str);
  k.Save(ss);
  v.insert(v.end(), k_str.begin(), k_str.end());
  return v;
}

/**
 * Concatenate two byteblocks into vector of unsigned char
 */
std::vector<unsigned char> concat_byteblocks(CryptoPP::SecByteBlock &b1,
                                             CryptoPP::SecByteBlock &b2) {
  // Convert byteblocks to strings
  std::string b1_str = byteblock_to_string(b1);
  std::string b2_str = byteblock_to_string(b2);

  // Concat strings to vec
  std::vector<unsigned char> v;
  v.insert(v.end(), b1_str.begin(), b1_str.end());
  v.insert(v.end(), b2_str.begin(), b2_str.end());
  return v;
}

/**
 * Concatenate a byteblock and certificate into vector of unsigned char
 */
std::vector<unsigned char>
concat_byteblock_and_cert(CryptoPP::SecByteBlock &b,
                          RegistrarToVoter_Certificate_Message &cert) {
  // Convert byteblock to strings, serialize cert
  std::string b_str = byteblock_to_string(b);

  std::vector<unsigned char> cert_data;
  cert.serialize(cert_data);

  // Concat string and data to vec.
  std::vector<unsigned char> v;
  v.insert(v.end(), b_str.begin(), b_str.end());
  v.insert(v.end(), cert_data.begin(), cert_data.end());
  return v;
}

/**
 * Concatenate a vote and zkp into vector of unsigned char
 */
std::vector<unsigned char> concat_votes_and_zkps(Votes_Struct &votes,
                                               VoteZKPs_Struct &zkps,
                                               Vote_Struct &vote_count,
                                               Count_ZKPs_Struct &count_zkps) {
  // Serialize vote and zkp.
  std::vector<unsigned char> votes_data;
  votes.serialize(votes_data);
  std::vector<unsigned char> zkps_data;
  zkps.serialize(zkps_data);
  std::vector<unsigned char> vote_count_data;
  vote_count.serialize(vote_count_data);
  std::vector<unsigned char> count_zkps_data;
  count_zkps.serialize(count_zkps_data);

  // Concat data to vec.
  std::vector<unsigned char> v;
  v.insert(v.end(), votes_data.begin(), votes_data.end());
  v.insert(v.end(), zkps_data.begin(), zkps_data.end());
  v.insert(v.end(), vote_count_data.begin(), vote_count_data.end());
  v.insert(v.end(), count_zkps_data.begin(), count_zkps_data.end());
  return v;
}