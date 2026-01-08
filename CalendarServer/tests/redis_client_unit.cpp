#include <iostream>
#include <string>
#include <cassert>
#include "../src/cache/Resp.h"

using namespace cache;

int main() {
    
    std::string s = resp_encode({"SET", "key", "value"});
    
    if (s.find("*3\r\n") != 0) { std::cerr << "resp_encode header wrong: " << s << "\n"; return 1; }
    if (s.find("$3\r\nSET\r\n") == std::string::npos) { std::cerr << "resp_encode missing SET\n"; return 1; }

    
    auto a = resp_parse("+OK\r\n");
    if (!a.has_value() || a->type != RespType::SimpleString || a->str != "OK") { std::cerr << "simple parse failed\n"; return 1; }

    
    auto b = resp_parse(":123\r\n");
    if (!b.has_value() || b->type != RespType::Integer || b->integer != 123) { std::cerr << "int parse failed\n"; return 1; }

    
    auto c = resp_parse("$5\r\nhello\r\n");
    if (!c.has_value() || c->type != RespType::BulkString || c->str != "hello") { std::cerr << "bulk parse failed\n"; return 1; }

    
    auto d = resp_parse("$-1\r\n");
    if (!d.has_value() || d->type != RespType::Null) { std::cerr << "null bulk failed\n"; return 1; }

    
    auto e = resp_parse("*2\r\n$3\r\nfoo\r\n:1\r\n");
    if (!e.has_value() || e->type != RespType::Array || e->arr.size() != 2) { std::cerr << "array parse failed\n"; return 1; }

    
    auto bad = resp_parse("$5\r\nhe");
    if (bad.has_value()) { std::cerr << "malformed should fail\n"; return 1; }

    std::cout << "redis_client_unit ok\n";
    return 0;
}
