#pragma once

#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

#include <boost/chrono.hpp>
#include <boost/thread.hpp>
#include <crypto++/cryptlib.h>
#include <crypto++/dsa.h>
#include <crypto++/filters.h>
#include <crypto++/hex.h>
#include <crypto++/integer.h>
#include <crypto++/nbtheory.h>

// ================================================
// MESSAGE TYPES
// ================================================

namespace MessageType {
enum T {
  HMACTagged_Wrapper = 1,
  UserToServer_DHPublicValue_Message = 2,
  ServerToUser_DHPublicValue_Message = 3,
  VoterToRegistrar_Register_Message = 4,
  RegistrarToVoter_Certificate_Message = 5,
  Vote_Struct = 6,
  VoteZKP_Struct = 7,
  VoterToTallyer_Vote_Message = 8,
  TallyerToWorld_Vote_Message = 9,
  PartialDecryption_Struct = 10,
  DecryptionZKP_Struct = 11,
  ArbiterToWorld_PartialDecryption_Message = 12,
  Count_ZKP_Struct = 13,
  Count_ZKPs_Struct = 14,
  Votes_Struct = 15,
  VoteZKPs_Struct = 16,
  PartialDecryptions_Struct = 17,
  DecryptionZKPs_Struct = 18
};
};
MessageType::T get_message_type(std::vector<unsigned char> &data);

// ================================================
// SERIALIZABLE
// ================================================

struct Serializable {
  virtual void serialize(std::vector<unsigned char> &data) = 0;
  virtual int deserialize(std::vector<unsigned char> &data) = 0;
};

// serializers.
int put_bool(bool b, std::vector<unsigned char> &data);
int put_string(std::string s, std::vector<unsigned char> &data);
int put_integer(CryptoPP::Integer i, std::vector<unsigned char> &data);

// serializing helper
void add_size_param(std::vector<unsigned char> &data, size_t &size_param);

// deserializers
int get_bool(bool *b, std::vector<unsigned char> &data, int idx);
int get_string(std::string *s, std::vector<unsigned char> &data, int idx);
int get_integer(CryptoPP::Integer *i, std::vector<unsigned char> &data,
                int idx);

// ================================================
// WRAPPERS
// ================================================

struct HMACTagged_Wrapper : public Serializable {
  std::vector<unsigned char> payload;
  CryptoPP::SecByteBlock iv;
  std::string mac;

  void serialize(std::vector<unsigned char> &data);
  int deserialize(std::vector<unsigned char> &data);
};

// ================================================
// KEY EXCHANGE
// ================================================

struct UserToServer_DHPublicValue_Message : public Serializable {
  CryptoPP::SecByteBlock public_value;

  void serialize(std::vector<unsigned char> &data);
  int deserialize(std::vector<unsigned char> &data);
};

struct ServerToUser_DHPublicValue_Message : public Serializable {
  CryptoPP::SecByteBlock server_public_value;
  CryptoPP::SecByteBlock user_public_value;
  std::string server_signature; // computed on server_value + user_value

  void serialize(std::vector<unsigned char> &data);
  int deserialize(std::vector<unsigned char> &data);
};

// ================================================
// VOTER <==> REGISTRAR
// ================================================

struct VoterToRegistrar_Register_Message : public Serializable {
  std::string id;
  CryptoPP::DSA::PublicKey user_verification_key;

  void serialize(std::vector<unsigned char> &data);
  int deserialize(std::vector<unsigned char> &data);
};

struct RegistrarToVoter_Certificate_Message : public Serializable {
  std::string id;
  CryptoPP::DSA::PublicKey verification_key;
  std::string registrar_signature; // computed on id + verification_key

  void serialize(std::vector<unsigned char> &data);
  int deserialize(std::vector<unsigned char> &data);
};

// ================================================
// VOTER <==> TALLYER
// ================================================

// Struct for a vote (a, b) = (g^r, pk^r * g^v)
struct Vote_Struct : public Serializable {
  CryptoPP::Integer a;
  CryptoPP::Integer b;

  void serialize(std::vector<unsigned char> &data);
  int deserialize(std::vector<unsigned char> &data);
};

struct Votes_Struct : public Serializable {
  std::vector<Vote_Struct> votes;

  void serialize(std::vector<unsigned char> &data);
  int deserialize(std::vector<unsigned char> &data);
};

// Struct for a dcp zkp of vote (a, b):
// (aβ, bβ, cβ, rβ) = (g^r, pk^r, cβ, r''β)
struct VoteZKP_Struct : public Serializable {
  CryptoPP::Integer a0;
  CryptoPP::Integer a1;
  CryptoPP::Integer b0;
  CryptoPP::Integer b1;
  CryptoPP::Integer c0;
  CryptoPP::Integer c1;
  CryptoPP::Integer r0;
  CryptoPP::Integer r1;

  void serialize(std::vector<unsigned char> &data);
  int deserialize(std::vector<unsigned char> &data);
};

struct VoteZKPs_Struct : public Serializable {
  std::vector<VoteZKP_Struct> zkps;

  void serialize(std::vector<unsigned char> &data);
  int deserialize(std::vector<unsigned char> &data);
};

struct Count_ZKP_Struct : public Serializable {
  CryptoPP::Integer a_i;
  CryptoPP::Integer b_i;
  CryptoPP::Integer c_i;
  CryptoPP::Integer r_i;

  void serialize(std::vector<unsigned char> &data);
  int deserialize(std::vector<unsigned char> &data);
};

struct Count_ZKPs_Struct : public Serializable {
  std::vector<Count_ZKP_Struct> count_zkps;

  void serialize(std::vector<unsigned char> &data);
  int deserialize(std::vector<unsigned char> &data);
};

struct VoterToTallyer_Vote_Message : public Serializable {
  RegistrarToVoter_Certificate_Message cert;
  Votes_Struct votes;
  VoteZKPs_Struct zkps;

  Vote_Struct vote_count;
  Count_ZKPs_Struct count_zkps;
  std::string voter_signature; // computed on votes, zkps, vote_count, and count_zkps

  void serialize(std::vector<unsigned char> &data);
  int deserialize(std::vector<unsigned char> &data);
};

struct TallyerToWorld_Vote_Message : public Serializable {
  Votes_Struct votes;
  VoteZKPs_Struct zkps;

  Vote_Struct vote_count;
  Count_ZKPs_Struct count_zkps;
  std::string tallyer_signature; // computed on votes, zkps, vote_count, and count_zkps

  void serialize(std::vector<unsigned char> &data);
  int deserialize(std::vector<unsigned char> &data);
};

// ================================================
// ARBITER <==> WORLD
// ================================================

// Struct for a pd of `aggregate_ciphertext` (d) = (g^{r sk_i})
struct PartialDecryption_Struct : public Serializable {
  CryptoPP::Integer d;
  Vote_Struct aggregate_ciphertext;

  void serialize(std::vector<unsigned char> &data);
  int deserialize(std::vector<unsigned char> &data);
};

struct PartialDecryptions_Struct : public Serializable {
  std::vector<PartialDecryption_Struct> decs;

  void serialize(std::vector<unsigned char> &data);
  int deserialize(std::vector<unsigned char> &data);
};

// Struct for a pd zkp of vote (a, b): (u, v, s) = (g^r, a^r, s)
struct DecryptionZKP_Struct : public Serializable {
  CryptoPP::Integer u;
  CryptoPP::Integer v;
  CryptoPP::Integer s;

  void serialize(std::vector<unsigned char> &data);
  int deserialize(std::vector<unsigned char> &data);
};

struct DecryptionZKPs_Struct : public Serializable {
  std::vector<DecryptionZKP_Struct> zkps;

  void serialize(std::vector<unsigned char> &data);
  int deserialize(std::vector<unsigned char> &data);
};

struct ArbiterToWorld_PartialDecryption_Message : public Serializable {
  std::string arbiter_id;
  std::string arbiter_vk_path;
  PartialDecryptions_Struct decs;
  DecryptionZKPs_Struct zkps;

  void serialize(std::vector<unsigned char> &data);
  int deserialize(std::vector<unsigned char> &data);
};


// ================================================
// SIGNING HELPERS
// ================================================

std::vector<unsigned char>
concat_string_and_dsakey(std::string &s, CryptoPP::DSA::PublicKey &k);
std::vector<unsigned char> concat_byteblocks(CryptoPP::SecByteBlock &b1,
                                             CryptoPP::SecByteBlock &b2);
std::vector<unsigned char>
concat_byteblock_and_cert(CryptoPP::SecByteBlock &b,
                          RegistrarToVoter_Certificate_Message &cert);
std::vector<unsigned char> concat_votes_and_zkps(Votes_Struct &votes,
                                               VoteZKPs_Struct &zkps,
                                               Vote_Struct &vote_count,
                                               Count_ZKPs_Struct &count_zkps);
