#include "../../include/pkg/election.hpp"
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
 * Generate Vote and ZKP.
 */
std::pair<Vote_Struct, VoteZKP_Struct>
ElectionClient::GenerateVote(CryptoPP::Integer vote, CryptoPP::Integer pk) {
  // TODO: implement me!
  CryptoPP::AutoSeededRandomPool a_seed;
  CryptoPP::Integer r(a_seed, 1, DL_P-1);

  // g^r
  CryptoPP::Integer a = CryptoPP::ModularExponentiation(DL_G, r, DL_P);
  
  CryptoPP::Integer pk_r = CryptoPP::ModularExponentiation(pk, r, DL_P);
  CryptoPP::Integer g_v = CryptoPP::ModularExponentiation(DL_G, vote, DL_P);

  // g^v * pk^r
  CryptoPP::Integer b = (pk_r * g_v) % DL_P;

  Vote_Struct vote_struct;
  vote_struct.a = a;
  vote_struct.b = b;

  VoteZKP_Struct zkp;
  // handle zero in the default case
  if (vote == CryptoPP::Integer::Zero()) {
    std::cout<<"Handling zero"<<std::endl;

    // c1
    CryptoPP::AutoSeededRandomPool a_c1;
    CryptoPP::Integer c1(a_c1, 1, DL_Q-1);
    zkp.c1 = c1;

    // r_1''
    CryptoPP::AutoSeededRandomPool a_r1_p;
    CryptoPP::Integer r1_p(a_r1_p, 1, DL_Q-1);
    zkp.r1 = r1_p;

    // b'
    CryptoPP::Integer b_p = (b * CryptoPP::EuclideanMultiplicativeInverse(DL_G, DL_P)) % DL_P;

    // a_1'
    CryptoPP::Integer a_c1_inv = CryptoPP::EuclideanMultiplicativeInverse(CryptoPP::ModularExponentiation(a, zkp.c1, DL_P), DL_P);
    zkp.a1 = (CryptoPP::ModularExponentiation(DL_G, zkp.r1, DL_P) * a_c1_inv) % DL_P;

    // b_1'
    CryptoPP::Integer b_p_c1_inv = CryptoPP::EuclideanMultiplicativeInverse(CryptoPP::ModularExponentiation(b_p, zkp.c1, DL_P), DL_P);
    zkp.b1 = (CryptoPP::ModularExponentiation(pk, zkp.r1, DL_P) * b_p_c1_inv) % DL_P;
    
    CryptoPP::AutoSeededRandomPool a_r0;
    CryptoPP::Integer r0(a_r0, 1, DL_Q-1);

    // a_0'
    zkp.a0 = CryptoPP::ModularExponentiation(DL_G, r0, DL_P);

    // b_0'
    zkp.b0 = CryptoPP::ModularExponentiation(pk, r0, DL_P);

    // c
    CryptoPP::Integer c = hash_vote_zkp(pk, a, b, zkp.a0, zkp.b0, zkp.a1, zkp.b1);
    zkp.c0 = (c - zkp.c1) % DL_Q;

    // r_0''
    zkp.r0 = (r0 + ((zkp.c0 * r) % DL_Q)) % DL_Q;
  } else {
    
    // c_0
    CryptoPP::AutoSeededRandomPool a_c0;
    CryptoPP::Integer c0(a_c0, 1, DL_Q-1);
    zkp.c0 = c0;

    // r_0''
    CryptoPP::AutoSeededRandomPool a_r0_p;
    CryptoPP::Integer r0_p(a_r0_p, 1, DL_Q-1);
    zkp.r0 = r0_p;

    // a_0'
    CryptoPP::Integer a_c0_inv = CryptoPP::EuclideanMultiplicativeInverse(CryptoPP::ModularExponentiation(a, zkp.c0, DL_P), DL_P);
    zkp.a0 = (CryptoPP::ModularExponentiation(DL_G, zkp.r0, DL_P) * a_c0_inv) % DL_P;

    // b_0'
    CryptoPP::Integer b_c0_inv = CryptoPP::EuclideanMultiplicativeInverse(CryptoPP::ModularExponentiation(b, zkp.c0, DL_P), DL_P);
    zkp.b0 = (CryptoPP::ModularExponentiation(pk, zkp.r0, DL_P) * b_c0_inv) % DL_P;

    CryptoPP::AutoSeededRandomPool a_r1;
    CryptoPP::Integer r1(a_r1, 1, DL_Q-1);

    // a_1'
    zkp.a1 = CryptoPP::ModularExponentiation(DL_G, r1, DL_P);

    // b_1'
    zkp.b1 = CryptoPP::ModularExponentiation(pk, r1, DL_P);

    //c_1
    CryptoPP::Integer c = hash_vote_zkp(pk, a, b, zkp.a0, zkp.b0, zkp.a1, zkp.b1);
    zkp.c1 = (c - zkp.c0) % DL_Q;

    // r_1''
    zkp.r1 = (r1 + ((zkp.c1 * r) % DL_Q)) % DL_Q;
  }

  return std::make_pair(vote_struct, zkp);
}

/**
 * Verify vote zkp.
 */
bool ElectionClient::VerifyVoteZKP(std::pair<Vote_Struct, VoteZKP_Struct> vote,
                                   CryptoPP::Integer pk) {
  // TODO: implement me!
  Vote_Struct vote_info = vote.first;
  VoteZKP_Struct zkp = vote.second;

  // g^{r_0''} = a_0' * a^{c_0}
  CryptoPP::Integer g_r0 = CryptoPP::ModularExponentiation(DL_G, zkp.r0, DL_P);
  CryptoPP::Integer g_r0_check = 
    (zkp.a0 * CryptoPP::ModularExponentiation(vote_info.a, zkp.c0, DL_P)) % DL_P;

  // g^{r_1''} = a_1' * a^{c_1}
  CryptoPP::Integer g_r1 = CryptoPP::ModularExponentiation(DL_G, zkp.r1, DL_P);
  CryptoPP::Integer g_r1_check = 
    (zkp.a1 * CryptoPP::ModularExponentiation(vote_info.a, zkp.c1, DL_P)) % DL_P;

  // pk^{r_0''} = b_0' * b^{c_0}
  CryptoPP::Integer pk_r0 = CryptoPP::ModularExponentiation(pk, zkp.r0, DL_P);
  CryptoPP::Integer pk_r0_check = 
    (zkp.b0 * CryptoPP::ModularExponentiation(vote_info.b, zkp.c0, DL_P)) % DL_P;

  // pk^{r_1''} = b_1' * (b/g)^{c_1}
  CryptoPP::Integer pk_r1 = CryptoPP::ModularExponentiation(pk, zkp.r1, DL_P);
  CryptoPP::Integer b_p = 
    (vote_info.b * CryptoPP::EuclideanMultiplicativeInverse(DL_G, DL_P)) % DL_P;
  CryptoPP::Integer pk_r1_check = 
    (zkp.b1 * CryptoPP::ModularExponentiation(b_p, zkp.c1, DL_P)) % DL_P;

  // c_0 + c_1 = H(...)
  CryptoPP::Integer c0_plus_c1 = (zkp.c0 + zkp.c1) % DL_Q;
  CryptoPP::Integer c = hash_vote_zkp(pk, vote_info.a, vote_info.b, zkp.a0, zkp.b0, zkp.a1, zkp.b1) % DL_Q;

  return (g_r0 == g_r0_check) && (g_r1 == g_r1_check) && (pk_r0 == pk_r0_check) && (pk_r1 == pk_r1_check) && (c0_plus_c1 == c);
}

/**
 * Generate partial decryption and zkp.
 */
std::pair<PartialDecryption_Struct, DecryptionZKP_Struct>
ElectionClient::PartialDecrypt(Vote_Struct combined_vote, CryptoPP::Integer pk,
                               CryptoPP::Integer sk) {
  // TODO: implement me!

  // generate the partial decryption
  PartialDecryption_Struct decryption_struct;
  decryption_struct.d = CryptoPP::ModularExponentiation(combined_vote.a, sk, DL_P);
  decryption_struct.aggregate_ciphertext = combined_vote;

  // generate zkp for partial decryption
  CryptoPP::AutoSeededRandomPool r_seed;
  CryptoPP::Integer r(r_seed, 1, DL_Q-1);

  DecryptionZKP_Struct zkp;
  zkp.v = CryptoPP::ModularExponentiation(DL_G, r, DL_P);
  zkp.u = CryptoPP::ModularExponentiation(combined_vote.a, r, DL_P);

  CryptoPP::Integer sigma = hash_dec_zkp(pk, combined_vote.a, combined_vote.b, zkp.u, zkp.v);
  CryptoPP::Integer s = (r + ((sigma * sk) % DL_Q)) % DL_Q;

  zkp.s = s;

  return std::make_pair(decryption_struct, zkp);
}

/**
 * Verify partial decryption zkp.
 */
bool ElectionClient::VerifyPartialDecryptZKP(
    ArbiterToWorld_PartialDecryption_Message a2w_dec_s, CryptoPP::Integer pki) {
  // TODO: implement me!
  CryptoPP::Integer A = a2w_dec_s.zkp.v;
  CryptoPP::Integer B = a2w_dec_s.zkp.u;
  CryptoPP::Integer s = a2w_dec_s.zkp.s;

  // sigma
  CryptoPP::Integer sigma = hash_dec_zkp(pki, a2w_dec_s.dec.aggregate_ciphertext.a, a2w_dec_s.dec.aggregate_ciphertext.b, B, A);

  // g^s
  CryptoPP::Integer g_s = CryptoPP::ModularExponentiation(DL_G, s, DL_P);

  CryptoPP::Integer g_s_check = (A * CryptoPP::ModularExponentiation(pki, sigma, DL_P)) % DL_P;

  // c1^s
  CryptoPP::Integer c1_s = CryptoPP::ModularExponentiation(a2w_dec_s.dec.aggregate_ciphertext.a, s, DL_P);

  CryptoPP::Integer c1_s_check = (B * CryptoPP::ModularExponentiation(a2w_dec_s.dec.d, sigma, DL_P)) % DL_P;

  return (g_s == g_s_check) && (c1_s == c1_s_check);
}

/**
 * Combine votes into one using homomorphic encryption.
 */
Vote_Struct ElectionClient::CombineVotes(std::vector<VoteRow> all_votes) {
  // TODO: implement me!
  CryptoPP::Integer c1 = CryptoPP::Integer::One();
  CryptoPP::Integer c2 = CryptoPP::Integer::One();

  for (int i=0; i<all_votes.size(); i++) {
    VoteRow row = all_votes[i];
    c1 = (c1 * row.vote.a) % DL_P;
    c2 = (c2 * row.vote.b) % DL_P;
  }

  Vote_Struct total_vote;
  total_vote.a = c1;
  total_vote.b = c2;

  return total_vote;
}

/**
 * Combine partial decryptions into final result.
 */
CryptoPP::Integer ElectionClient::CombineResults(
    Vote_Struct combined_vote,
    std::vector<PartialDecryptionRow> all_partial_decryptions) {
  // TODO: implement me!
  CryptoPP::Integer result_exp = combined_vote.b;

  for (int i=0; i<all_partial_decryptions.size(); i++) {
    PartialDecryptionRow row = all_partial_decryptions[i];
    CryptoPP::Integer d_inv = CryptoPP::EuclideanMultiplicativeInverse(row.dec.d, DL_P);
    result_exp = (result_exp * d_inv) % DL_P;
  }

  CryptoPP::Integer votes = CryptoPP::Integer::Zero();
  while (true) {
    CryptoPP::Integer g_votes = CryptoPP::ModularExponentiation(DL_G, votes, DL_P);
    if (g_votes == result_exp) {
      break;
    }

    votes += CryptoPP::Integer::One();
  }

  return votes;
}
