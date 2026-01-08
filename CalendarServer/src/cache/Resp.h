#pragma once
#include <string>
#include <vector>
#include <cstdint>
#include <optional>

namespace cache {

enum class RespType { SimpleString, Error, Integer, BulkString, Array, Null };

struct RespValue {
    RespType type;
    std::string str; 
    int64_t integer = 0; 
    std::vector<RespValue> arr; 
};


std::string resp_encode(const std::vector<std::string>& args);


std::optional<RespValue> resp_parse(const std::string& buf);

} 
