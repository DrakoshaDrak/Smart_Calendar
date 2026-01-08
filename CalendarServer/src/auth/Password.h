#pragma once

#include <string>

namespace auth {

std::string hash_password(const std::string& password);
bool verify_password(const std::string& password, const std::string& hash);

}
