#include "Password.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#include <stdexcept>
#include <sstream>
#include <iomanip>
#include <vector>
#include <cstring>

#ifdef HAVE_ARGON2
#include <argon2.h>
#endif

namespace auth {

#ifdef HAVE_ARGON2

std::string hash_password(const std::string& password) {
    
    const uint32_t t_cost = 2;
    const uint32_t m_cost = (1 << 16); 
    const uint32_t parallelism = 1;
    const size_t salt_len = 16;
    const size_t hash_len = 32;

    std::vector<unsigned char> salt(salt_len);
    if (RAND_bytes(salt.data(), (int)salt_len) != 1) throw std::runtime_error("RAND_bytes failed");

    
    size_t encoded_len = argon2_encodedlen(t_cost, m_cost, parallelism, salt_len, hash_len, Argon2_id);
    std::vector<char> encoded(encoded_len + 1);
    int rc = argon2id_hash_encoded(t_cost, m_cost, parallelism,
                                   password.data(), password.size(),
                                   salt.data(), salt_len,
                                   hash_len, encoded.data(), encoded.size());
    if (rc != ARGON2_OK) throw std::runtime_error("argon2id_hash_encoded failed");
    return std::string(encoded.data());
}

bool verify_password(const std::string& password, const std::string& hash) {
    int rc = argon2id_verify(hash.c_str(), password.data(), password.size());
    return rc == ARGON2_OK;
}

#else




static std::string to_hex(const unsigned char* data, size_t len) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (size_t i = 0; i < len; ++i) oss << std::setw(2) << (int)data[i];
    return oss.str();
}

static inline int hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static std::vector<unsigned char> from_hex(const std::string& s) {
    if (s.empty() || (s.size() & 1)) return {};
    std::vector<unsigned char> out;
    out.reserve(s.size() / 2);
    for (size_t i = 0; i < s.size(); i += 2) {
        int hi = hexval(s[i]);
        int lo = hexval(s[i + 1]);
        if (hi < 0 || lo < 0) return {};
        out.push_back((unsigned char)((hi << 4) | lo));
    }
    return out;
}

std::string hash_password(const std::string& password) {
    const int iterations = 210000; 
    const size_t salt_len = 16;
    const size_t dk_len = 32;

    std::vector<unsigned char> salt(salt_len);
    if (RAND_bytes(salt.data(), (int)salt_len) != 1) throw std::runtime_error("RAND_bytes failed");

    std::vector<unsigned char> dk(dk_len);
    if (!PKCS5_PBKDF2_HMAC(password.c_str(), (int)password.size(), salt.data(), (int)salt.size(), iterations, EVP_sha256(), (int)dk_len, dk.data())) {
        throw std::runtime_error("PKCS5_PBKDF2_HMAC failed");
    }

    std::ostringstream oss;
    
    oss << "pbkdf2$" << iterations << "$" << to_hex(salt.data(), salt.size()) << "$" << to_hex(dk.data(), dk.size());
    return oss.str();
}

bool verify_password(const std::string& password, const std::string& hash) {
    
    
    try {
        size_t p = 0;
        auto next = [&](char delim){ size_t q = hash.find(delim, p); std::string part = (q==std::string::npos)?hash.substr(p):hash.substr(p, q-p); p = (q==std::string::npos)?hash.size():q+1; return part; };
        std::string alg = next('$');
        if (alg != "pbkdf2") return false;
        std::string it_s = next('$');
        if (it_s.empty()) return false;
        long iterations = std::stol(it_s);
        
        if (iterations < 100000 || iterations > 2000000) return false;
        std::string salt_hex = next('$');
        std::string dk_hex = next('$');
        auto salt = from_hex(salt_hex);
        auto dk = from_hex(dk_hex);
        
        if (salt.size() != 16) return false;
        if (dk.size() != 32) return false;
        std::vector<unsigned char> out(dk.size());
        if (!PKCS5_PBKDF2_HMAC(password.c_str(), (int)password.size(), salt.data(), (int)salt.size(), (int)iterations, EVP_sha256(), (int)out.size(), out.data())) return false;
        
        if (CRYPTO_memcmp(out.data(), dk.data(), out.size()) != 0) return false;
        return true;
    } catch (...) {
        return false;
    }
}

#endif

}
