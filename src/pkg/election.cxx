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
std::tuple<Vote_Struct, VoteZKP_Struct, CryptoPP::Integer>
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

  return std::make_tuple(vote_struct, zkp, r);
}

/**
 * Generates votes and zkps
*/
std::tuple<Votes_Struct, VoteZKPs_Struct, CryptoPP::Integer>
ElectionClient::GenerateVotes(std::vector<CryptoPP::Integer> votes, CryptoPP::Integer pk) {

  std::vector<Vote_Struct> votes_vec;
  std::vector<VoteZKP_Struct> zkps_vec;
  CryptoPP::Integer r = CryptoPP::Integer::Zero();

  for (auto &vote : votes) {
    std::tuple<Vote_Struct, VoteZKP_Struct, CryptoPP::Integer> vote_and_zkp = ElectionClient::GenerateVote(vote, pk);
    votes_vec.push_back(std::get<0>(vote_and_zkp));
    zkps_vec.push_back(std::get<1>(vote_and_zkp));
    r += std::get<2>(vote_and_zkp);
  }
  Votes_Struct votes_struct;
  votes_struct.votes = votes_vec;
  VoteZKPs_Struct zkps_struct;
  zkps_struct.zkps = zkps_vec;

  return std::make_tuple(votes_struct, zkps_struct, r);
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
 * Verifies vote zkps
*/
bool ElectionClient::VerifyVoteZKPs(std::pair<Votes_Struct, VoteZKPs_Struct> votes, CryptoPP::Integer pk) {
  std::vector<Vote_Struct> vote_structs = votes.first.votes;
  std::vector<VoteZKP_Struct> zkps_structs = votes.second.zkps;

  for (int i=0; i<vote_structs.size(); i++) {
    std::pair<Vote_Struct, VoteZKP_Struct> vote = std::make_pair(vote_structs[i], zkps_structs[i]);
    if (!(ElectionClient::VerifyVoteZKP(vote, pk))) {
      return false;
    }
  }

  return true;
}

/**
 * Generates vote count zkp
*/
std::pair<Vote_Struct, Count_ZKPs_Struct> 
ElectionClient::GenerateCountZKPs(std::vector<Vote_Struct> votes, int num_votes, 
                                  CryptoPP::Integer r, CryptoPP::Integer pk) {
  CryptoPP::Integer c1 = CryptoPP::Integer::One();
  CryptoPP::Integer c2 = CryptoPP::Integer::One();

  for (int i=0; i<votes.size(); i++) {
    c1 = (c1 * votes[i].a) % DL_P;
    c2 = (c2 * votes[i].b) % DL_P;
  }

  Vote_Struct collective_vote;
  collective_vote.a = c1;
  collective_vote.b = c2;

  // simulate zkp for every i not equal to `num_votes`
  std::vector<Count_ZKP_Struct> count_zkps;
  CryptoPP::Integer c_sum = CryptoPP::Integer::Zero();
  for (int i=0; i<votes.size(); i++) {
    if (i == num_votes) {
      Count_ZKP_Struct count_zkp;
      count_zkps.push_back(count_zkp);
      continue;
    }

    CryptoPP::AutoSeededRandomPool seed1;
    CryptoPP::Integer c(seed1, 1, DL_Q-1);
    c_sum = (c_sum + c) % DL_Q;

    CryptoPP::AutoSeededRandomPool seed2;
    CryptoPP::Integer r_pp(seed2, 1, DL_Q-1);

    CryptoPP::Integer pow(i);

    CryptoPP::Integer g_pow = CryptoPP::ModularExponentiation(DL_G, pow, DL_P);
    CryptoPP::Integer b_p = (c2 * CryptoPP::EuclideanMultiplicativeInverse(g_pow, DL_P)) % DL_P;

    CryptoPP::Integer g_r_pp = CryptoPP::ModularExponentiation(DL_G, r_pp, DL_P);
    CryptoPP::Integer a_c_i = CryptoPP::ModularExponentiation(c1, c, DL_P);

    CryptoPP::Integer pk_r_pp = CryptoPP::ModularExponentiation(pk, r_pp, DL_P);
    CryptoPP::Integer b_p_c_i = CryptoPP::ModularExponentiation(b_p, c, DL_P);

    Count_ZKP_Struct count_zkp;
    count_zkp.a_i = (g_r_pp * CryptoPP::EuclideanMultiplicativeInverse(a_c_i, DL_P)) % DL_P;
    count_zkp.b_i = (pk_r_pp * CryptoPP::EuclideanMultiplicativeInverse(b_p_c_i, DL_P)) % DL_P;
    count_zkp.c_i = c;
    count_zkp.r_i = r_pp;
    count_zkps.push_back(count_zkp);
  }

  // zkp for `num_votes`
  Count_ZKP_Struct &num_votes_zkp = count_zkps[num_votes];

  CryptoPP::AutoSeededRandomPool seed;
  CryptoPP::Integer r_i(seed, 1, DL_Q-1);
  num_votes_zkp.a_i = CryptoPP::ModularExponentiation(DL_G, r_i, DL_P);
  num_votes_zkp.b_i = CryptoPP::ModularExponentiation(pk, r_i, DL_P);

  std::vector<CryptoPP::Integer> a_vec;
  std::vector<CryptoPP::Integer> b_vec;
  for (int i=0; i<count_zkps.size(); i++) {
    a_vec.push_back(count_zkps[i].a_i);
    b_vec.push_back(count_zkps[i].b_i);
  }

  CryptoPP::Integer c = hash_count_zkp(pk, c1, c2, a_vec, b_vec);
  CryptoPP::Integer c_i = (c_sum - c) % DL_Q;

  num_votes_zkp.c_i = c_i;
  num_votes_zkp.r_i = r_i + ((c_i * r) % DL_Q) % DL_Q;

  Count_ZKPs_Struct count_zkps_struct;
  count_zkps_struct.count_zkps = count_zkps;

  return std::make_pair(collective_vote, count_zkps_struct);
}

/**
 * Verifies vote count zkp
*/
bool ElectionClient::VerifyCountZKPs(std::pair<Vote_Struct, Count_ZKPs_Struct> vote_count, CryptoPP::Integer pk) {
  CryptoPP::Integer a = vote_count.first.a;
  CryptoPP::Integer b = vote_count.first.b;

  CryptoPP::Integer c_sum = CryptoPP::Integer::Zero();
  std::vector<CryptoPP::Integer> a_vec;
  std::vector<CryptoPP::Integer> b_vec;
  std::vector<Count_ZKP_Struct> count_zkps = vote_count.second.count_zkps;

  for (int i=0; i<count_zkps.size(); i++) {
    Count_ZKP_Struct count_zkp = count_zkps[i];
    CryptoPP::Integer g_r_pp = CryptoPP::ModularExponentiation(DL_G, count_zkp.r_i, DL_P);
    CryptoPP::Integer a_i_check = (count_zkp.a_i * (CryptoPP::ModularExponentiation(a, count_zkp.c_i, DL_P))) % DL_P;

    CryptoPP::Integer pk_r_pp = CryptoPP::ModularExponentiation(pk, count_zkp.r_i, DL_P);
    CryptoPP::Integer pow(i);
    CryptoPP::Integer g_k_inv = 
      CryptoPP::EuclideanMultiplicativeInverse(CryptoPP::ModularExponentiation(DL_G, pow, DL_P), DL_P);
    CryptoPP::Integer b_g_k_inv_c_i = CryptoPP::ModularExponentiation(((b * g_k_inv) % DL_P), count_zkp.c_i, DL_P);
    CryptoPP::Integer b_i_check = (count_zkp.b_i * b_g_k_inv_c_i) % DL_P;

    if (!(g_r_pp == a_i_check) || !(pk_r_pp == b_i_check)) {
      return false;
    }

    c_sum = (c_sum + count_zkp.c_i) % DL_Q;
    a_vec.push_back(count_zkp.a_i);
    b_vec.push_back(count_zkp.b_i);
  }

  CryptoPP::Integer c = hash_count_zkp(pk, a, b, a_vec, b_vec);
  return (c_sum == c);
}


/**
 * Generate partial decryption and zkp.
 */
std::pair<PartialDecryption_Struct, DecryptionZKP_Struct>
ElectionClient::PartialDecrypt(Vote_Struct combined_vote, CryptoPP::Integer pk, CryptoPP::Integer sk) {
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

std::pair<PartialDecryptions_Struct, DecryptionZKPs_Struct>
ElectionClient::PartialDecryptions(Votes_Struct combined_votes, CryptoPP::Integer pk, CryptoPP::Integer sk) {
  std::vector<Vote_Struct> votes = combined_votes.votes;

  std::vector<PartialDecryption_Struct> decs;
  std::vector<DecryptionZKP_Struct> zkps;

  for (auto &combined_vote : votes) {
    std::pair<PartialDecryption_Struct, DecryptionZKP_Struct> dec = 
      ElectionClient::PartialDecrypt(combined_vote, pk, sk);
    
    decs.push_back(dec.first);
    zkps.push_back(dec.second);
  }

  PartialDecryptions_Struct decs_struct;
  decs_struct.decs = decs;

  DecryptionZKPs_Struct zkps_struct;
  zkps_struct.zkps = zkps;

  return std::make_pair(decs_struct, zkps_struct);
}

/**
 * Verify partial decryption zkp.
 */
bool ElectionClient::VerifyPartialDecryptZKPs(
    ArbiterToWorld_PartialDecryption_Message a2w_dec_s, CryptoPP::Integer pki) {
  // TODO: implement me!

  std::vector<PartialDecryption_Struct> decs = a2w_dec_s.decs.decs;
  std::vector<DecryptionZKP_Struct> zkps = a2w_dec_s.zkps.zkps;

  for (int i=0; i<decs.size(); i++) {
    CryptoPP::Integer A = zkps[i].v;
    CryptoPP::Integer B = zkps[i].u;
    CryptoPP::Integer s = zkps[i].s;

    // sigma
    CryptoPP::Integer sigma = hash_dec_zkp(pki, decs[i].aggregate_ciphertext.a, decs[i].aggregate_ciphertext.b, B, A);

    // g^s
    CryptoPP::Integer g_s = CryptoPP::ModularExponentiation(DL_G, s, DL_P);

    CryptoPP::Integer g_s_check = (A * CryptoPP::ModularExponentiation(pki, sigma, DL_P)) % DL_P;

    // c1^s
    CryptoPP::Integer c1_s = CryptoPP::ModularExponentiation(decs[i].aggregate_ciphertext.a, s, DL_P);

    CryptoPP::Integer c1_s_check = (B * CryptoPP::ModularExponentiation(decs[i].d, sigma, DL_P)) % DL_P;

    if (!(g_s == g_s_check) or !(c1_s == c1_s_check)) {
      return false;
    }
  }

  return true;
}


/**
 * Combine votes into one using homomorphic encryption.
 */
Votes_Struct ElectionClient::CombineVotes(std::vector<VoteRow> all_votes, int num_candidates) {
  // TODO: implement me!

  std::vector<Vote_Struct> vote_structs;
  for (int i=0; i<num_candidates; i++) { // iterate over each candidate
    CryptoPP::Integer c1 = CryptoPP::Integer::One();
    CryptoPP::Integer c2 = CryptoPP::Integer::One();

    for (int j=0; j<all_votes.size(); j++) { // combines for each candidate
      VoteRow row = all_votes[j];
      c1 = (c1 * row.votes.votes[i].a) % DL_P;
      c2 = (c2 * row.votes.votes[i].b) % DL_P;
    }

    Vote_Struct total_vote;
    total_vote.a = c1;
    total_vote.b = c2;

    vote_structs.push_back(total_vote);
  }

  Votes_Struct collective_votes;
  collective_votes.votes = vote_structs;

  return collective_votes;
}

/**
 * Combine partial decryptions into final result.
 */
std::vector<CryptoPP::Integer> ElectionClient::CombineResults(
    Votes_Struct combined_votes,
    std::vector<PartialDecryptionRow> all_partial_decryptions) {
  // TODO: implement me!

  std::vector<CryptoPP::Integer> combined_results;
  std::vector<Vote_Struct> combined_votes_vecs = combined_votes.votes;

  for (int i=0; i<combined_votes_vecs.size(); i++) { // iterate over each candidate
    Vote_Struct combined_vote = combined_votes_vecs[i];

    CryptoPP::Integer result_exp = combined_vote.b;

    for (auto &row : all_partial_decryptions) { // iterate over each arbiter
      CryptoPP::Integer d = row.decs.decs[i].d;
      CryptoPP::Integer d_inv = CryptoPP::EuclideanMultiplicativeInverse(d, DL_P);
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

    combined_results.push_back(votes);
  }

  return combined_results;
}