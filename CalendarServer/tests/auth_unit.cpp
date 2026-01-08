
#include <iostream>
#include <string>
#include <optional>
#include "auth/Password.h"
#include "auth/Jwt.h"

int main() {
    
    const std::string pw = "pass123";
    std::string hash;
    try {
        hash = auth::hash_password(pw);
    } catch (const std::exception& e) {
        std::cerr << "hash_password threw: " << e.what() << '\n';
        return 1;
    }
    if (hash.empty()) { std::cerr << "hash_password returned empty string\n"; return 1; }
    if (!auth::verify_password("pass123", hash)) { std::cerr << "verify_password(correct) failed\n"; return 1; }
    if (auth::verify_password("wrong", hash)) { std::cerr << "verify_password(wrong) unexpectedly succeeded\n"; return 1; }
    if (auth::verify_password("", hash)) { std::cerr << "verify_password(empty) unexpectedly succeeded\n"; return 1; }

    if (auth::verify_password("pass123", "garbage")) { std::cerr << "verify_password(garbage) unexpectedly succeeded\n"; return 1; }
    if (auth::verify_password("pass123", "pbkdf2$notanumber$salt$dk")) { std::cerr << "verify_password(notanumber) unexpectedly succeeded\n"; return 1; }
    if (auth::verify_password("pass123", "pbkdf2$1000$zzzz$abcd")) { std::cerr << "verify_password(nonhex salt) unexpectedly succeeded\n"; return 1; }
    if (auth::verify_password("pass123", "pbkdf2$1000$0a0b")) { std::cerr << "verify_password(missing parts) unexpectedly succeeded\n"; return 1; }

#ifdef HAVE_ARGON2
    
    if (auth::verify_password("pass123", "$argon2id$v=19$m=65536,t=2,p=1$zzzz$abcd")) { std::cerr << "verify_password(argon2 garbage) unexpectedly succeeded\n"; return 1; }
#endif

    
    auth::Claims c;
    c.sub = "u1";
    c.email = "a@b.c";
    c.iat = 1700000000; 
    
    c.exp = 2000000000; 
    const std::string secret = "secret";
    std::string token;
    try {
        token = auth::create_jwt(c, secret);
    } catch (const std::exception& e) {
        std::cerr << "create_jwt threw: " << e.what() << '\n';
        return 1;
    }
    auto ok = auth::verify_jwt(token, secret);
    if (!ok.has_value()) { std::cerr << "verify_jwt(valid) failed\n"; return 1; }
    if (ok->sub != c.sub) { std::cerr << "verify_jwt: sub mismatch\n"; return 1; }
    if (ok->email != c.email) { std::cerr << "verify_jwt: email mismatch\n"; return 1; }

    if (auth::verify_jwt(token, "wrongsecret").has_value()) { std::cerr << "verify_jwt(wrongsecret) unexpectedly succeeded\n"; return 1; }

    
    std::string corrupted = token;
    size_t last_dot = corrupted.rfind('.');
    if (last_dot == std::string::npos) { std::cerr << "token format unexpected (no dot)\n"; return 1; }
    size_t sig_start = last_dot + 1;
    if (sig_start >= corrupted.size()) { std::cerr << "token signature segment empty\n"; return 1; }
    
    const std::string b64set = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    
    size_t idx = sig_start; 
    char orig = corrupted[idx];
    char repl = orig;
    for (char ch : b64set) { if (ch != orig) { repl = ch; break; } }
    corrupted[idx] = repl;
    if (auth::verify_jwt(corrupted, secret).has_value()) { std::cerr << "verify_jwt(corrupted sig) unexpectedly succeeded\n"; return 1; }

    
    auth::Claims c_exp = c;
    c_exp.exp = c_exp.iat - 10;
    std::string token_exp = auth::create_jwt(c_exp, secret);
    if (auth::verify_jwt(token_exp, secret).has_value()) { std::cerr << "verify_jwt(expired) unexpectedly succeeded\n"; return 1; }

    
    if (auth::verify_jwt("abc.def", secret).has_value()) { std::cerr << "verify_jwt(malformed 2-part) unexpectedly succeeded\n"; return 1; }
    if (auth::verify_jwt("abc", secret).has_value()) { std::cerr << "verify_jwt(malformed 1-part) unexpectedly succeeded\n"; return 1; }

    std::cout << "auth_unit ok\n";
    return 0;
}
