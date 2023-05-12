#pragma once

#include <crypto++/cryptlib.h>
#include <crypto++/dh.h>
#include <crypto++/dh2.h>
#include <crypto++/dsa.h>
#include <crypto++/integer.h>
#include <crypto++/nbtheory.h>
#include <crypto++/osrng.h>

#include "../../include-shared/config.hpp"
#include "../../include-shared/constants.hpp"
#include "../../include-shared/messages.hpp"
#include "../../include-shared/util.hpp"
#include "../../include/drivers/cli_driver.hpp"
#include "../../include/drivers/db_driver.hpp"

class ElectionClient {
public:
  static std::tuple<Vote_Struct, VoteZKP_Struct, CryptoPP::Integer>
  GenerateVote(CryptoPP::Integer vote, CryptoPP::Integer pk);
  static std::tuple<Votes_Struct, VoteZKPs_Struct, CryptoPP::Integer>
  GenerateVotes(std::vector<CryptoPP::Integer> votes, CryptoPP::Integer pk);

  static bool VerifyVoteZKP(std::pair<Vote_Struct, VoteZKP_Struct> vote, CryptoPP::Integer pk);
  static bool VerifyVoteZKPs(std::pair<Votes_Struct, VoteZKPs_Struct> votes, CryptoPP::Integer pk);

  static std::pair<Vote_Struct, Count_ZKPs_Struct>
  GenerateCountZKPs(std::vector<Vote_Struct> votes, int num_votes, CryptoPP::Integer r, CryptoPP::Integer pk);

  static bool VerifyCountZKPs(std::pair<Vote_Struct, Count_ZKPs_Struct> vote_count, CryptoPP::Integer pk);

  static std::pair<PartialDecryption_Struct, DecryptionZKP_Struct>
  PartialDecrypt(Vote_Struct combined_vote, CryptoPP::Integer pk,
                 CryptoPP::Integer sk);
  
  static std::pair<PartialDecryptions_Struct, DecryptionZKPs_Struct>
  PartialDecryptions(Votes_Struct combined_votes, CryptoPP::Integer pk, CryptoPP::Integer sk);

  static bool
  VerifyPartialDecryptZKPs(ArbiterToWorld_PartialDecryption_Message a2w_dec_s,
                          CryptoPP::Integer pki);

  static Votes_Struct CombineVotes(std::vector<VoteRow> all_votes, int num_candidates);
  
  static std::vector<CryptoPP::Integer>
  CombineResults(Votes_Struct combined_vote,
                 std::vector<PartialDecryptionRow> all_partial_decryptions);
};
