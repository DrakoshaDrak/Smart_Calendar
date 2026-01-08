#include "Router.h"
#include <boost/beast/http.hpp>

void Router::add_route(std::string method, std::string path, Handler h) {
    Key k{std::move(method), std::move(path)};
    routes_.emplace(std::move(k), std::move(h));
}

Response Router::route(const Request& req) const {
    Key k{std::string(req.method_string()), std::string(req.target())};
    auto it = routes_.find(k);
    if (it == routes_.end()) {
        bool path_exists = false;
        for (const auto& p : routes_) {
            if (p.first.path == k.path) { path_exists = true; break; }
        }
        if (path_exists) {
            Response res{boost::beast::http::status::method_not_allowed, req.version()};
            res.set(boost::beast::http::field::content_type, "application/json; charset=utf-8");
            res.keep_alive(req.keep_alive());
            res.body() = "{\"error\":\"method not allowed\"}";
            res.prepare_payload();
            return res;
        }
        Response res{boost::beast::http::status::not_found, req.version()};
    res.set(boost::beast::http::field::content_type, "application/json; charset=utf-8");
        res.keep_alive(req.keep_alive());
        res.body() = "{\"error\":\"not found\"}";
        res.prepare_payload();
        return res;
    }
    return it->second(req);
}
