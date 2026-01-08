#pragma once

#include "Request.h"
#include "Response.h"
#include <string>
#include <functional>
#include <unordered_map>
#include <vector>

class Router {
public:
    using Handler = std::function<Response(const Request&)>;
    void add_route(std::string method, std::string path, Handler h);
    Response route(const Request& req) const;
private:
    struct Key { std::string method; std::string path; };
    struct KeyHash {
        size_t operator()(Key const& k) const noexcept { return std::hash<std::string>()(k.method + "#" + k.path); }
    };
    struct KeyEq { bool operator()(Key const& a, Key const& b) const noexcept { return a.method==b.method && a.path==b.path; } };
    std::unordered_map<Key, Handler, KeyHash, KeyEq> routes_;
};
