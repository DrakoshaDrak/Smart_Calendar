#pragma once

#include <string>
#include <optional>
#include <unordered_map>

namespace auth {

struct Claims {
    std::string sub;
    std::string email;
    int64_t iat = 0;
    int64_t exp = 0;
};

std::string create_jwt(const Claims& c, const std::string& secret);


std::optional<Claims> verify_jwt(const std::string& token, const std::string& secret);

}
