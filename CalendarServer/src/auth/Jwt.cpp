#include "Jwt.h"
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <string>
#include <cstring>
#include <vector>
#include <ctime>
#include <sstream>
#include <iomanip>
#include <stdexcept>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/crypto.h>

namespace {

std::string escape_json(const std::string& s) {
    std::string out; out.reserve(s.size()+4);
    for (char c : s) {
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\b': out += "\\b"; break;
            case '\f': out += "\\f"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default: out += c; break;
        }
    }
    return out;
}

static std::string json_build_header() {
    return std::string("{\"alg\":\"HS256\",\"typ\":\"JWT\"}");
}

// very small parser to extract string fields and integer fields from a flat JSON object
static std::string json_extract_string(const std::string& js, const std::string& key) {
    // Strict, minimal extractor: no escapes supported in values.
    std::string q = "\"" + key + "\"";
    size_t pos = 0;
    while (true) {
        pos = js.find(q, pos);
        if (pos == std::string::npos) return {};
        // check char before key: should be '{' or ',' (allow spaces)
        size_t before = pos;
        while (before > 0 && isspace((unsigned char)js[before-1])) --before;
        if (before == 0 || (js[before-1] != '{' && js[before-1] != ',')) { pos += q.size(); continue; }
        // find colon
        size_t colon = js.find(':', pos + q.size());
        if (colon == std::string::npos) return {};
        // find opening quote for value
        size_t val_start = colon + 1;
        while (val_start < js.size() && isspace((unsigned char)js[val_start])) ++val_start;
        if (val_start >= js.size() || js[val_start] != '"') return {};
        ++val_start;
        // find closing quote and decode escapes minimally
        std::string out;
        size_t i = val_start;
        for (; i < js.size(); ++i) {
            char c = js[i];
            if (c == '"') { ++i; break; }
            if (c != '\\') { out += c; continue; }
            // escape sequence
            ++i; if (i >= js.size()) return {};
            char e = js[i];
            switch (e) {
                case '"': out += '"'; break;
                case '\\': out += '\\'; break;
                case '/': out += '/'; break;
                case 'b': out += '\b'; break;
                case 'f': out += '\f'; break;
                case 'n': out += '\n'; break;
                case 'r': out += '\r'; break;
                case 't': out += '\t'; break;
                case 'u': {
                    // parse \uXXXX (hex)
                    if (i + 4 >= js.size()) return {};
                    unsigned int code = 0;
                    for (int k=1;k<=4;++k) {
                        char ch = js[i+k];
                        code <<= 4;
                        if (ch >= '0' && ch <= '9') code += ch - '0';
                        else if (ch >= 'a' && ch <= 'f') code += 10 + (ch - 'a');
                        else if (ch >= 'A' && ch <= 'F') code += 10 + (ch - 'A');
                        else return {};
                    }
                    // append as UTF-8 (basic BMP handling)
                    if (code <= 0x7f) out += static_cast<char>(code);
                    else if (code <= 0x7ff) {
                        out += static_cast<char>(0xc0 | ((code >> 6) & 0x1f));
                        out += static_cast<char>(0x80 | (code & 0x3f));
                    } else {
                        out += static_cast<char>(0xe0 | ((code >> 12) & 0x0f));
                        out += static_cast<char>(0x80 | ((code >> 6) & 0x3f));
                        out += static_cast<char>(0x80 | (code & 0x3f));
                    }
                    i += 4;
                    break;
                }
                default: return {};
            }
        }
        if (i > js.size()) return {};
        return out;
    }
}

static int64_t json_extract_int(const std::string& js, const std::string& key) {
    // Strict int extractor: ensure key occurs as token and value is digits (allow leading spaces and optional '-').
    std::string q = "\"" + key + "\"";
    size_t pos = 0;
    while (true) {
        pos = js.find(q, pos);
        if (pos == std::string::npos) return 0;
        // check preceding context
        size_t before = pos;
        while (before > 0 && isspace((unsigned char)js[before-1])) --before;
        if (before == 0 || (js[before-1] != '{' && js[before-1] != ',')) { pos += q.size(); continue; }
        size_t colon = js.find(':', pos + q.size());
        if (colon == std::string::npos) return 0;
        size_t start = colon + 1;
        while (start < js.size() && isspace((unsigned char)js[start])) ++start;
        size_t end = start;
        if (end < js.size() && js[end] == '-') ++end;
        while (end < js.size() && js[end] >= '0' && js[end] <= '9') ++end;
        if (end == start || (end == start+1 && js[start] == '-')) return 0;
        // ensure next char is ',' or '}' or space
        size_t after = end;
        while (after < js.size() && isspace((unsigned char)js[after])) ++after;
        if (after < js.size() && js[after] != ',' && js[after] != '}') return 0;
        try { return std::stoll(js.substr(start, end - start)); } catch(...) { return 0; }
    }
}


std::string base64url_encode(const std::string& in) {
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO* bmem = BIO_new(BIO_s_mem());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    b64 = BIO_push(b64, bmem);
    BIO_write(b64, in.data(), in.size());
    BIO_flush(b64);
    BUF_MEM* bptr;
    BIO_get_mem_ptr(b64, &bptr);
    std::string out(bptr->data, bptr->length);
    BIO_free_all(b64);
    // url-safe
    for (auto& c : out) {
        if (c == '+') c = '-';
        else if (c == '/') c = '_';
    }
    while (!out.empty() && out.back() == '=') out.pop_back();
    return out;
}

std::string base64url_decode(const std::string& in) {
    std::string s = in;
    for (auto& c : s) {
        if (c == '-') c = '+';
        else if (c == '_') c = '/';
    }
    while (s.size() % 4) s.push_back('=');
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO* bmem = BIO_new_mem_buf(s.data(), s.size());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bmem = BIO_push(b64, bmem);
    std::vector<char> out(s.size());
    int outlen = BIO_read(bmem, out.data(), out.size());
    BIO_free_all(bmem);
    if (outlen <= 0) return std::string();
    return std::string(out.data(), outlen);
}

std::string hmac_sha256(const std::string& key, const std::string& data) {
    unsigned int len = EVP_MAX_MD_SIZE;
    unsigned char md[EVP_MAX_MD_SIZE];
    HMAC(EVP_sha256(), key.data(), key.size(), (unsigned char*)data.data(), data.size(), md, &len);
    return std::string(reinterpret_cast<char*>(md), len);
}

}

namespace auth {

std::string create_jwt(const Claims& c, const std::string& secret) {
    std::string header_s = json_build_header();
    std::ostringstream oss;
    oss << "{";
    oss << "\"sub\":\"" << escape_json(c.sub) << "\",";
    oss << "\"email\":\"" << escape_json(c.email) << "\",";
    oss << "\"iat\":" << c.iat << ",";
    oss << "\"exp\":" << c.exp;
    oss << "}";
    std::string payload_s = oss.str();
    std::string to_sign = base64url_encode(header_s) + "." + base64url_encode(payload_s);
    std::string sig = hmac_sha256(secret, to_sign);
    std::string token = to_sign + "." + base64url_encode(sig);
    return token;
}

std::optional<Claims> verify_jwt(const std::string& token, const std::string& secret) {
    // reject absurdly large tokens
    const size_t MAX_TOKEN = 8 * 1024; // 8KB
    if (token.size() == 0 || token.size() > MAX_TOKEN) return {};
    size_t p1 = token.find('.');
    if (p1 == std::string::npos) return {};
    size_t p2 = token.find('.', p1 + 1);
    if (p2 == std::string::npos) return {};
    std::string h_enc = token.substr(0, p1);
    std::string p_enc = token.substr(p1 + 1, p2 - p1 -1);
    std::string s_enc = token.substr(p2 + 1);
    std::string header_s = base64url_decode(h_enc);
    std::string payload_s = base64url_decode(p_enc);
    std::string sig = base64url_decode(s_enc);
    std::string to_sign = h_enc + "." + p_enc;
    std::string expected_sig = hmac_sha256(secret, to_sign);
    // constant time compare
    if (sig.size() != expected_sig.size()) return {};
    if (CRYPTO_memcmp(sig.data(), expected_sig.data(), sig.size()) != 0) return {};
    // validate header fields
    auto alg = json_extract_string(header_s, "alg");
    if (alg != "HS256") return {};
    auto typ = json_extract_string(header_s, "typ");
    if (!typ.empty() && typ != "JWT") return {};
    Claims cl;
    cl.sub = json_extract_string(payload_s, "sub");
    cl.email = json_extract_string(payload_s, "email");
    cl.iat = json_extract_int(payload_s, "iat");
    cl.exp = json_extract_int(payload_s, "exp");
    auto now = std::time(nullptr);
    if (cl.exp != 0 && now > cl.exp) return {};
    // optional: reject tokens issued far in the future
    if (cl.iat != 0 && cl.iat > now + 60) return {};
    return cl;
}

}
