#include "../include-shared/keyloaders.hpp"
#include "../include-shared/constants.hpp"
#include "../include-shared/util.hpp"

/**
 * Save the DSA key at the file.
 */
void SaveDSAPrivateKey(const std::string &filename,
                       const CryptoPP::PrivateKey &key) {
  key.Save(CryptoPP::FileSink(filename.c_str()).Ref());
}

/**
 * Load the DSA key from the file.
 */
void LoadDSAPrivateKey(const std::string &filename, CryptoPP::PrivateKey &key) {
  key.Load(CryptoPP::FileStore(filename.c_str()).Ref());

  CryptoPP::AutoSeededRandomPool rng;
  if (!key.Validate(rng, 3)) {
    throw std::runtime_error("DSA private key loading failed");
  }
}

/**
 * Save the DSA key at the file.
 */
void SaveDSAPublicKey(const std::string &filename,
                      const CryptoPP::PublicKey &key) {
  key.Save(CryptoPP::FileSink(filename.c_str()).Ref());
}

/**
 * Load the DSA key from the file.
 */
void LoadDSAPublicKey(const std::string &filename, CryptoPP::PublicKey &key) {
  key.Load(CryptoPP::FileStore(filename.c_str()).Ref());

  CryptoPP::AutoSeededRandomPool rng;
  if (!key.Validate(rng, 3)) {
    throw std::runtime_error("DSA public key loading failed");
  }
}

/**
 * Used to save server signature
 */
void SaveCertificate(const std::string &filename,
                     RegistrarToVoter_Certificate_Message &cert) {
  std::vector<unsigned char> cert_data;
  cert.serialize(cert_data);

  CryptoPP::StringSource(chvec2str(cert_data), true,
                         new CryptoPP::FileSink(filename.c_str()));
}

/**
 * User to load server signature
 */
void LoadCertificate(const std::string &filename,
                     RegistrarToVoter_Certificate_Message &cert) {
  std::string cert_str;
  CryptoPP::FileSource(filename.c_str(), true,
                       new CryptoPP::StringSink(cert_str));

  std::vector<unsigned char> cert_data = str2chvec(cert_str);
  cert.deserialize(cert_data);
}

/**
 * Save the PRG seed at the file.
 */
void SavePRGSeed(const std::string &filename,
                 const CryptoPP::SecByteBlock &seed) {
  CryptoPP::ArraySource(seed.data(), seed.size(), true,
                        new CryptoPP::FileSink(filename.c_str()));
}

/**
 * Load the PRG seed from the file.
 */
void LoadPRGSeed(const std::string &filename, CryptoPP::SecByteBlock &seed) {
  seed = CryptoPP::SecByteBlock(PRG_SIZE);
  CryptoPP::FileSource(filename.c_str(), true,
                       new CryptoPP::ArraySink(seed.data(), seed.size()));
}

/**
 * Save an integer at the file.
 */
void SaveInteger(const std::string &filename, const CryptoPP::Integer &i) {
  CryptoPP::StringSource(CryptoPP::IntToString(i), true,
                         new CryptoPP::FileSink(filename.c_str()));
}

/**
 * Load an integer from the file.
 */
void LoadInteger(const std::string &filename, CryptoPP::Integer *i) {
  std::string i_str;
  CryptoPP::FileSource(filename.c_str(), true, new CryptoPP::StringSink(i_str));
  *i = CryptoPP::Integer(i_str.c_str());
}

/**
 * Loads the election public key from the files provided.
 */
void LoadElectionPublicKey(const std::vector<std::string> &filenames,
                           CryptoPP::Integer *public_key) {
  CryptoPP::Integer final_key = CryptoPP::Integer::One();
  for (auto path : filenames) {
    CryptoPP::Integer key;
    LoadInteger(path, &key);
    final_key *= key;
  }
  *public_key = CryptoPP::Integer(final_key);
}
