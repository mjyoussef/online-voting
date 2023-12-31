#include <fstream>
#include <iostream>
#include <stdexcept>

#include "../../include-shared/util.hpp"
#include "../../include/drivers/db_driver.hpp"
#include "../../include/drivers/network_driver.hpp"

// ================================================
// INITIALIZATION
// ================================================

/**
 * Initialize DBDriver.
 */
DBDriver::DBDriver() {}

/**
 * Open a particular db file.
 */
int DBDriver::open(std::string dbpath) {
  return sqlite3_open(dbpath.c_str(), &this->db);
}

/**
 * Close db.
 */
int DBDriver::close() { return sqlite3_close(this->db); }

/**
 * Initialize tables.
 */
void DBDriver::init_tables() {
  // Lock db driver.
  std::unique_lock<std::mutex> lck(this->mtx);
  
  // create voter table
  std::string create_voter_query = "CREATE TABLE IF NOT EXISTS voter("
                                   "id TEXT PRIMARY KEY NOT NULL, "
                                   "verification_key TEXT NOT NULL, "
                                   "registrar_signature TEXT NOT NULL);";
  char *err;
  int exit = sqlite3_exec(this->db, create_voter_query.c_str(), NULL, 0, &err);
  if (exit != SQLITE_OK) {
    std::cerr << "Error creating table: " << err << std::endl;
  } else {
    std::cout << "Table created successfully" << std::endl;
  }

  // create vote table
  std::string create_vote_query = "CREATE TABLE IF NOT EXISTS vote("
                                  "votes TEXT PRIMARY KEY  NOT NULL, "
                                  "zkps TEXT NOT NULL, "
                                  "vote_count TEXT NOT NULL, "
                                  "count_zkps TEXT NOT NULL, "
                                  "signature TEXT NOT NULL);";
  exit = sqlite3_exec(this->db, create_vote_query.c_str(), NULL, 0, &err);
  if (exit != SQLITE_OK) {
    std::cerr << "Error creating table: " << err << std::endl;
  } else {
    std::cout << "Table created successfully" << std::endl;
  }

  // create partial_decryption table
  std::string create_partial_decryption_query =
      "CREATE TABLE IF NOT EXISTS partial_decryption("
      "arbiter_id TEXT PRIMARY KEY NOT NULL, "
      "arbiter_vk_path TEXT NOT NULL, "
      "decs TEXT NOT NULL, "
      "zkps TEXT NOT NULL);";
  exit = sqlite3_exec(this->db, create_partial_decryption_query.c_str(), NULL,
                      0, &err);
  if (exit != SQLITE_OK) {
    std::cerr << "Error creating table: " << err << std::endl;
  } else {
    std::cout << "Table created successfully" << std::endl;
  }

  // create voted table
  std::string create_voted_query = "CREATE TABLE IF NOT EXISTS voted("
                                   "id TEXT PRIMARY KEY NOT NULL);";
  exit = sqlite3_exec(this->db, create_voted_query.c_str(), NULL, 0, &err);
  if (exit != SQLITE_OK) {
    std::cerr << "Error creating table: " << err << std::endl;
  } else {
    std::cout << "Table created successfully" << std::endl;
  }
}

/**
 * Reset tables by dropping all.
 */
void DBDriver::reset_tables() {
  // Lock db driver.
  std::unique_lock<std::mutex> lck(this->mtx);
  
  // Get all table names
  std::vector<std::string> table_names;
  table_names.push_back("voter");
  table_names.push_back("vote");
  table_names.push_back("partial_decryption");
  table_names.push_back("voted");

  sqlite3_stmt *stmt;
  // For each table, drop it
  for (std::string table : table_names) {
    std::string delete_query = "DELETE FROM " + table;
    sqlite3_prepare_v2(this->db, delete_query.c_str(), delete_query.length(), &stmt,
                       nullptr);
    char *err;
    int exit = sqlite3_exec(this->db, delete_query.c_str(), NULL, 0, &err);
    if (exit != SQLITE_OK) {
      std::cerr << "Error dropping table: " << err << std::endl;
    }
  }

  // Finalize and return.
  int exit = sqlite3_finalize(stmt);
  if (exit != SQLITE_OK) {
    std::cerr << "Error resetting tables" << std::endl;
  }
}

// ================================================
// VOTER
// ================================================

/**
 * Find the given voter. Returns an empty voter if none was found.
 */
VoterRow DBDriver::find_voter(std::string id) {
  // Lock db driver.
  std::unique_lock<std::mutex> lck(this->mtx);
  
  std::string find_query = "SELECT id, verification_key, registrar_signature "
                           "FROM voter WHERE id = ?";

  // Prepare statement.
  sqlite3_stmt *stmt;
  sqlite3_prepare_v2(this->db, find_query.c_str(), find_query.length(), &stmt,
                     nullptr);
  sqlite3_bind_blob(stmt, 1, id.c_str(), id.length(), SQLITE_STATIC);

  // Retreive voter.
  VoterRow voter;
  std::string verification_key_str;
  if (sqlite3_step(stmt) == SQLITE_ROW) {
    for (int colIndex = 0; colIndex < sqlite3_column_count(stmt); colIndex++) {
      const void *raw_result = sqlite3_column_blob(stmt, colIndex);
      int num_bytes = sqlite3_column_bytes(stmt, colIndex);
      switch (colIndex) {
      case 0:
        voter.id = std::string((const char *)raw_result, num_bytes);;
        break;
      case 1:
        verification_key_str = std::string((const char *)raw_result, num_bytes);;
        break;
      case 2:
        voter.registrar_signature = std::string((const char *)raw_result, num_bytes);;
        break;
      }
    }
  }

  if (verification_key_str != "") {
    CryptoPP::StringSource ss(verification_key_str, true,
                              new CryptoPP::HexDecoder());
    voter.verification_key.Load(ss);
  }
  // Finalize and return.
  int exit = sqlite3_finalize(stmt);
  if (exit != SQLITE_OK) {
    std::cerr << "Error finding voter " << std::endl;
  }
  return voter;
}

/**
 * Insert the given voter; prints an error if violated a primary key constraint.
 */
VoterRow DBDriver::insert_voter(VoterRow voter) {
  // Lock db driver.
  std::unique_lock<std::mutex> lck(this->mtx);
  
  std::string insert_query = "INSERT INTO voter(id, verification_key, "
                             "registrar_signature) VALUES(?, ?, ?);";

  // Serialize voter fields.
  std::string verification_key_str;
  CryptoPP::HexEncoder ss(new CryptoPP::StringSink(verification_key_str));
  voter.verification_key.Save(ss);

  // Prepare statement.
  sqlite3_stmt *stmt;
  sqlite3_prepare_v2(this->db, insert_query.c_str(), insert_query.length(),
                     &stmt, nullptr);
  sqlite3_bind_blob(stmt, 1, voter.id.c_str(), voter.id.length(),
                    SQLITE_STATIC);
  sqlite3_bind_blob(stmt, 2, verification_key_str.c_str(),
                    verification_key_str.length(), SQLITE_STATIC);
  sqlite3_bind_blob(stmt, 3, voter.registrar_signature.c_str(),
                    voter.registrar_signature.length(), SQLITE_STATIC);

  // Run and return.
  sqlite3_step(stmt);
  int exit = sqlite3_finalize(stmt);
  if (exit != SQLITE_OK) {
    std::cerr << "Error inserting voter " << std::endl;
  }
  return voter;
}

// ================================================
// VOTE
// ================================================

/**
 * Return all votes.
 */
std::vector<VoteRow> DBDriver::all_votes() {
  // Lock db driver.
  std::unique_lock<std::mutex> lck(this->mtx);
  
  std::string find_query = "SELECT votes, zkps, vote_count, count_zkps, signature FROM vote";

  // Prepare statement.
  sqlite3_stmt *stmt;
  sqlite3_prepare_v2(this->db, find_query.c_str(), find_query.length(), &stmt, nullptr);

  // Retreive vote.
  std::vector<VoteRow> res;
  while (sqlite3_step(stmt) == SQLITE_ROW) {
    VoteRow vote;
    for (int colIndex = 0; colIndex < sqlite3_column_count(stmt); colIndex++) {
      const void *raw_result = sqlite3_column_blob(stmt, colIndex);
      int num_bytes = sqlite3_column_bytes(stmt, colIndex);
      std::vector<unsigned char> data;
      switch (colIndex) {
      case 0:
        data = str2chvec(std::string((const char *)raw_result, num_bytes));
        vote.votes.deserialize(data);
        break;
      case 1:
        data = str2chvec(std::string((const char *)raw_result, num_bytes));
        vote.zkps.deserialize(data);
        break;
      case 2:
        data = str2chvec(std::string((const char *)raw_result, num_bytes));
        vote.vote_count.deserialize(data);
        break;
      case 3:
        data = str2chvec(std::string((const char *)raw_result, num_bytes));
        vote.count_zkps.deserialize(data);
        break;
      case 4:
        vote.tallyer_signature = std::string((const char *)raw_result, num_bytes);
        break;
      }
    }
    res.push_back(vote);
  }

  // Finalize and return.
  int exit = sqlite3_finalize(stmt);
  if (exit != SQLITE_OK) {
    std::cerr << "Error finding vote " << std::endl;
  }
  return res;
}

/**
 * Find the given vote. Returns an empty vote if none was found.
 */
VoteRow DBDriver::find_vote(Vote_Struct vote_s) {
  // Lock db driver.
  std::unique_lock<std::mutex> lck(this->mtx);
  
  std::string find_query =
      "SELECT votes, zkps, vote_count, count_zkps, signature FROM vote WHERE vote = ?";

  // Serialize cert.
  std::vector<unsigned char> vote_data;
  vote_s.serialize(vote_data);
  std::string vote_str = chvec2str(vote_data);

  // Prepare statement.
  sqlite3_stmt *stmt;
  sqlite3_prepare_v2(this->db, find_query.c_str(), find_query.length(), &stmt, nullptr);
  sqlite3_bind_blob(stmt, 1, vote_str.c_str(), vote_str.length(), SQLITE_STATIC);

  // Retreive vote.
  VoteRow vote;
  if (sqlite3_step(stmt) == SQLITE_ROW) {
    for (int colIndex = 0; colIndex < sqlite3_column_count(stmt); colIndex++) {
      const void *raw_result = sqlite3_column_blob(stmt, colIndex);
      int num_bytes = sqlite3_column_bytes(stmt, colIndex);
      std::vector<unsigned char> data;
      switch (colIndex) {
      case 0:
        data = str2chvec(std::string((const char *)raw_result, num_bytes));
        vote.votes.deserialize(data);
        break;
      case 1:
        data = str2chvec(std::string((const char *)raw_result, num_bytes));
        vote.zkps.deserialize(data);
        break;
      case 2:
        data = str2chvec(std::string((const char *)raw_result, num_bytes));
        vote.vote_count.deserialize(data);
        break;
      case 3:
        data = str2chvec(std::string((const char *)raw_result, num_bytes));
        vote.count_zkps.deserialize(data);
        break;
      case 4:
        vote.tallyer_signature = std::string((const char *)raw_result, num_bytes);
        break;
      }
    }
  }

  // Finalize and return.
  int exit = sqlite3_finalize(stmt);
  if (exit != SQLITE_OK) {
    std::cerr << "Error finding vote " << std::endl;
  }
  return vote;
}

/**
 * Insert the given vote; prints an error if violated a primary key constraint.
 */
VoteRow DBDriver::insert_vote(VoteRow vote) {
  // Lock db driver.
  std::unique_lock<std::mutex> lck(this->mtx);
  
  std::string insert_query =
      "INSERT INTO vote(votes, zkps, vote_count, count_zkps, signature) VALUES(?, ?, ?, ?, ?);";

  // Serialize vote fields.
  std::vector<unsigned char> votes_data;
  vote.votes.serialize(votes_data);
  std::string votes_str = chvec2str(votes_data);

  std::vector<unsigned char> zkps_data;
  vote.zkps.serialize(zkps_data);
  std::string zkps_str = chvec2str(zkps_data);

  std::vector<unsigned char> vote_count_data;
  vote.vote_count.serialize(vote_count_data);
  std::string vote_count_str = chvec2str(vote_count_data);

  std::vector<unsigned char> count_zkps_data;
  vote.count_zkps.serialize(count_zkps_data);
  std::string count_zkps_str = chvec2str(count_zkps_data);

  std::string sign_str = vote.tallyer_signature;

  // Prepare statement.
  sqlite3_stmt *stmt;
  sqlite3_prepare_v2(this->db, insert_query.c_str(), insert_query.length(),
                     &stmt, nullptr);
  sqlite3_bind_blob(stmt, 1, votes_str.c_str(), votes_str.length(), SQLITE_STATIC);
  sqlite3_bind_blob(stmt, 2, zkps_str.c_str(), zkps_str.length(), SQLITE_STATIC);
  sqlite3_bind_blob(stmt, 3, vote_count_str.c_str(), vote_count_str.length(), SQLITE_STATIC);
  sqlite3_bind_blob(stmt, 4, count_zkps_str.c_str(), count_zkps_str.length(), SQLITE_STATIC);
  sqlite3_bind_blob(stmt, 5, sign_str.c_str(), sign_str.length(), SQLITE_STATIC);

  // Run and return.
  sqlite3_step(stmt);
  int exit = sqlite3_finalize(stmt);
  if (exit != SQLITE_OK) {
    std::cerr << "Error inserting vote " << std::endl;
  }
  return vote;
}

// ================================================
// PARTIAL_DECRYPTIONS
// ================================================

/**
 * Return all partial decryptions.
 */
std::vector<PartialDecryptionRow>
DBDriver::DBDriver::all_partial_decryptions() {
  // Lock db driver.
  std::unique_lock<std::mutex> lck(this->mtx);
  
  std::string find_query = "SELECT arbiter_id, arbiter_vk_path, "
                           "decs, zkps FROM partial_decryption";

  // Prepare statement.
  sqlite3_stmt *stmt;
  sqlite3_prepare_v2(this->db, find_query.c_str(), find_query.length(), &stmt,
                     nullptr);

  // Retreive partial_decryption.
  std::vector<PartialDecryptionRow> res;
  while (sqlite3_step(stmt) == SQLITE_ROW) {
    PartialDecryptionRow partial_decryption;
    for (int colIndex = 0; colIndex < sqlite3_column_count(stmt); colIndex++) {
      const void *raw_result = sqlite3_column_blob(stmt, colIndex);
      int num_bytes = sqlite3_column_bytes(stmt, colIndex);
      std::vector<unsigned char> data;
      switch (colIndex) {
      case 0:
        partial_decryption.arbiter_id = std::string((const char *)raw_result, num_bytes);
        break;
      case 1:
        partial_decryption.arbiter_vk_path = std::string((const char *)raw_result, num_bytes);
        break;
      case 2:
        data = str2chvec(std::string((const char *)raw_result, num_bytes));
        partial_decryption.decs.deserialize(data);
        break;
      case 3:
        data = str2chvec(std::string((const char *)raw_result, num_bytes));
        partial_decryption.zkps.deserialize(data);
        break;
      }
    }
    res.push_back(partial_decryption);
  }

  // Finalize and return.
  int exit = sqlite3_finalize(stmt);
  if (exit != SQLITE_OK) {
    std::cerr << "Error finding partial_decryption " << std::endl;
  }
  return res;
}

/**
 * Find the given partial_decryption. Returns an empty partial_decryption if
 * none was found.
 */
PartialDecryptionRow DBDriver::find_partial_decryption(std::string arbiter_id) {
  // Lock db driver.
  std::unique_lock<std::mutex> lck(this->mtx);
  
  std::string find_query =
      "SELECT arbiter_id, arbiter_vk_path, decs, zkps FROM "
      "partial_decryption WHERE arbiter_id = ?";

  // Prepare statement.
  sqlite3_stmt *stmt;
  sqlite3_prepare_v2(this->db, find_query.c_str(), find_query.length(), &stmt,
                     nullptr);
  sqlite3_bind_blob(stmt, 1, arbiter_id.c_str(), arbiter_id.length(),
                    SQLITE_STATIC);

  // Retreive partial_decryption.
  PartialDecryptionRow partial_decryption;
  if (sqlite3_step(stmt) == SQLITE_ROW) {
    for (int colIndex = 0; colIndex < sqlite3_column_count(stmt); colIndex++) {
      const void *raw_result = sqlite3_column_blob(stmt, colIndex);
      int num_bytes = sqlite3_column_bytes(stmt, colIndex);
      std::vector<unsigned char> data;
      switch (colIndex) {
      case 0:
        partial_decryption.arbiter_id = std::string((const char *)raw_result, num_bytes);
        break;
      case 1:
        partial_decryption.arbiter_vk_path = std::string((const char *)raw_result, num_bytes);
        break;
      case 2:
        data = str2chvec(std::string((const char *)raw_result, num_bytes));
        partial_decryption.decs.deserialize(data);
        break;
      case 3:
        data = str2chvec(std::string((const char *)raw_result, num_bytes));
        partial_decryption.zkps.deserialize(data);
        break;
      }
    }
  }

  // Finalize and return.
  int exit = sqlite3_finalize(stmt);
  if (exit != SQLITE_OK) {
    std::cerr << "Error finding partial_decryption " << std::endl;
  }
  return partial_decryption;
}

/**
 * Insert the given partial_decryption; prints an error if violated a primary
 * key constraint.
 */
PartialDecryptionRow
DBDriver::insert_partial_decryption(PartialDecryptionRow partial_decryption) {
  // Lock db driver.
  std::unique_lock<std::mutex> lck(this->mtx);
  

  std::string insert_query =
      "INSERT OR REPLACE INTO partial_decryption(arbiter_id, "
      "arbiter_vk_path, decs, zkps) VALUES(?, ?, ?, ?);";

  // Serialize pd fields.
  std::vector<unsigned char> partial_decryption_data;
  partial_decryption.decs.serialize(partial_decryption_data);
  std::string decs_str = chvec2str(partial_decryption_data);

  std::vector<unsigned char> zkp_data;
  partial_decryption.zkps.serialize(zkp_data);
  std::string zkps_str = chvec2str(zkp_data);

  // Prepare statement.
  sqlite3_stmt *stmt;
  sqlite3_prepare_v2(this->db, insert_query.c_str(), insert_query.length(),
                     &stmt, nullptr);
  sqlite3_bind_blob(stmt, 1, partial_decryption.arbiter_id.c_str(),
                    partial_decryption.arbiter_id.length(), SQLITE_STATIC);
  sqlite3_bind_blob(stmt, 2, partial_decryption.arbiter_vk_path.c_str(),
                    partial_decryption.arbiter_vk_path.length(), SQLITE_STATIC);
  sqlite3_bind_blob(stmt, 3, decs_str.c_str(), decs_str.length(), SQLITE_STATIC);
  sqlite3_bind_blob(stmt, 4, zkps_str.c_str(), zkps_str.length(), SQLITE_STATIC);

  // Run and return.
  sqlite3_step(stmt);
  int exit = sqlite3_finalize(stmt);
  if (exit != SQLITE_OK) {
    std::cerr << "Error inserting partial_decryption " << std::endl;
  }
  return partial_decryption;
}

// ================================================
// VOTED
// ================================================

bool DBDriver::voter_voted(std::string id) {
  // Lock db driver.
  std::unique_lock<std::mutex> lck(this->mtx);
  
  std::string find_query = "SELECT 1 FROM voted WHERE id = ?";

  // Prepare statement.
  sqlite3_stmt *stmt;
  sqlite3_prepare_v2(this->db, find_query.c_str(), find_query.length(), &stmt,
                     nullptr);
  sqlite3_bind_blob(stmt, 1, id.c_str(), id.length(), SQLITE_STATIC);
  // Check if exists.
  bool result;
  int rc = sqlite3_step(stmt);
  if (rc == SQLITE_DONE) // no result
    result = false;
  else if (sqlite3_column_type(stmt, 0) == SQLITE_NULL) // result is NULL
    result = false;
  else { // some valid result
    result = true;
  }

  // Finalize and return.
  int exit = sqlite3_finalize(stmt);
  if (exit != SQLITE_OK) {
    std::cerr << "Error finding vote " << std::endl;
  }
  return result;
}

std::string DBDriver::insert_voted(std::string id) {
  // Lock db driver.
  std::unique_lock<std::mutex> lck(this->mtx);
  
  std::string insert_query = "INSERT INTO voted(id) VALUES(?);";

  // Prepare statement.
  sqlite3_stmt *stmt;
  sqlite3_prepare_v2(this->db, insert_query.c_str(), insert_query.length(),
                     &stmt, nullptr);
  sqlite3_bind_blob(stmt, 1, id.c_str(), id.length(), SQLITE_STATIC);

  // Run and return.
  sqlite3_step(stmt);
  int exit = sqlite3_finalize(stmt);
  if (exit != SQLITE_OK) {
    std::cerr << "Error inserting voted status " << std::endl;
  }
  return id;
}
