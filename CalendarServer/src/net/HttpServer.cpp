#include "HttpServer.h"
#include "Request.h"
#include "Response.h"
#include "observability/Metrics.h"
#include "observability/Logging.h"
#include "../auth/Password.h"
#include "../auth/Jwt.h"
#include "../recurrence/Materializer.h"
#include <cstdlib>
#include <optional>
#include <boost/beast/http.hpp>
#include <chrono>
#include <algorithm>
#include <atomic>
#include <boost/asio/thread_pool.hpp>
#include "MiniJson.h"
#include "../cache/CacheKeys.h"


static std::string url_decode(std::string_view s) {
    std::string out; out.reserve(s.size());
    for (size_t i = 0; i < s.size(); ++i) {
        char c = s[i];
        if (c == '%') {
            if (i + 2 >= s.size()) return out; 
            auto hex = [&](char h)->int {
                if (h >= '0' && h <= '9') return h - '0';
                if (h >= 'a' && h <= 'f') return 10 + (h - 'a');
                if (h >= 'A' && h <= 'F') return 10 + (h - 'A');
                return -1;
            };
            int hi = hex(s[i+1]); int lo = hex(s[i+2]); if (hi < 0 || lo < 0) return out;
            out.push_back(char((hi << 4) | lo)); i += 2;
        } else if (c == '+') out.push_back(' ');
        else out.push_back(c);
    }
    return out;
}


static bool parse_yyyy_mm(std::string_view s, int& y, int& m) {
    if (s.size() < 7) return false;
    if (!(isdigit((unsigned char)s[0])&&isdigit((unsigned char)s[1])&&isdigit((unsigned char)s[2])&&isdigit((unsigned char)s[3]))) return false;
    if (s[4] != '-') return false;
    if (!(isdigit((unsigned char)s[5])&&isdigit((unsigned char)s[6]))) return false;
    y = (s[0]-'0')*1000 + (s[1]-'0')*100 + (s[2]-'0')*10 + (s[3]-'0');
    m = (s[5]-'0')*10 + (s[6]-'0');
    if (m < 1 || m > 12) return false;
    return true;
}

static std::pair<std::string,std::string> month_range_utc_from_ts(std::string_view iso_ts) {
    int y=0,m=0;
    if (!parse_yyyy_mm(iso_ts, y, m)) return {"",""};
    int ny = y, nm = m + 1;
    if (nm == 13) { nm = 1; ny++; }
    char buf1[32]; char buf2[32];
    std::snprintf(buf1, sizeof(buf1), "%04d-%02d-01T00:00:00Z", y, m);
    std::snprintf(buf2, sizeof(buf2), "%04d-%02d-01T00:00:00Z", ny, nm);
    return {std::string(buf1), std::string(buf2)};
}


static std::string normalize_iso_z(std::string_view s_in) {
    std::string s = std::string(s_in);
    if (s.empty()) return s;
    
    if (s.size() > 10 && s[10] == ' ') s[10] = 'T';
    
    if (s.size() >= 3) {
        if (s.size() >= 3 && s.size() >= 3 && s.rfind("+00:00") == s.size() - 6) {
            s.erase(s.size() - 6);
            s.push_back('Z');
        } else if (s.size() >= 3 && s.rfind("+0000") == s.size() - 5) {
            s.erase(s.size() - 5);
            s.push_back('Z');
        } else if (s.size() >= 3 && s.rfind("+00") == s.size() - 3) {
            s.erase(s.size() - 3);
            s.push_back('Z');
        }
    }
    
    return s;
}


static bool parse_iso_z_utc(const std::string& s, std::tm& tm_out) {
    std::istringstream iss(s);
    iss >> std::get_time(&tm_out, "%Y-%m-%dT%H:%M:%SZ");
    if (iss.fail()) return false;
    return true;
}

static std::string format_iso_z_utc(std::time_t t) {
    std::tm tm{};
    gmtime_r(&t, &tm);
    char buf[32];
    std::snprintf(buf, sizeof(buf), "%04d-%02d-%02dT%02d:%02d:%02dZ",
        tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
        tm.tm_hour, tm.tm_min, tm.tm_sec);
    return std::string(buf);
}

static bool add_seconds_iso_z(const std::string& in, int delta, std::string& out) {
    std::tm tm{};
    if (!parse_iso_z_utc(in, tm)) return false;
    
    std::time_t t = timegm(&tm);
    if (t == (std::time_t)-1) return false;
    t += delta;
    out = format_iso_z_utc(t);
    return true;
}


static std::string build_created_event_json(const std::vector<std::optional<std::string>>& row) {
    auto s = [](const std::optional<std::string>& o){ return o.has_value() ? o.value() : std::string(); };
    std::ostringstream ss;
    ss << '{';
    ss << "\"id\":\"" << json_escape_resp(s(row[0])) << "\",";
    ss << "\"calendar_id\":\"" << json_escape_resp(s(row[1])) << "\",";
    ss << "\"title\":\"" << json_escape_resp(s(row[2])) << "\",";
    ss << "\"description\":";
    if (row[3].has_value()) ss << '"' << json_escape_resp(row[3].value()) << '"'; else ss << "null";
    ss << ",\"start_ts\":\"" << json_escape_resp(normalize_iso_z(s(row[4]))) << '\"';
    ss << ",\"end_ts\":";
    if (row[5].has_value()) ss << '"' << json_escape_resp(normalize_iso_z(s(row[5]))) << '"'; else ss << "null";
    ss << ",\"created_by\":\"" << json_escape_resp(s(row[6])) << '\"';
    ss << ",\"created_at\":\"" << json_escape_resp(normalize_iso_z(s(row[7]))) << '\"';
    ss << ",\"updated_at\":\"" << json_escape_resp(normalize_iso_z(s(row[8]))) << '\"';
    ss << '}';
    return ss.str();
}


static std::optional<int> parse_role_from_membership_row(const db::DbResult& r) {
    if (!r.ok || r.rows.empty() || r.rows[0].size() < 3) return std::nullopt;
    const auto& col = r.rows[0][2];
    if (!col.has_value()) return std::optional<int>(0);
    return json_parse_int32_strict(col);
}


static inline bool is_valid_role_value(int r) {
    return r == 0 || r == 1 || r == 2;
}


static inline bool actor_may_assign_role(int actor_role, int requested_role) {
    if (!is_valid_role_value(requested_role)) return false;
    
    if (requested_role >= 1 && actor_role != 2) return false;
    return true;
}


static inline bool is_valid_role(int r) { return is_valid_role_value(r); }
static inline bool can_assign_role(int actor_role, int requested_role) { return actor_may_assign_role(actor_role, requested_role); }

namespace beast = boost::beast;
namespace http = beast::http;
namespace net = boost::asio;

struct Session : std::enable_shared_from_this<Session> {
    net::ip::tcp::socket socket;
    beast::flat_buffer buffer;
    net::steady_timer read_timer;
    Router& router;
    unsigned http_version = 11;
    Request req;
    bool draining_ = false;
    std::array<char, 4096> drain_buf_{};
    int drain_seconds_ = 5; 
    std::chrono::steady_clock::time_point start_ts;
    bool metrics_enabled;
    bool access_log;
    std::shared_ptr<RedisClient> redis;
    std::shared_ptr<db::DbPool> db;
    std::optional<auth::Claims> auth_claims;
    std::string jwt_secret;
    std::shared_ptr<boost::asio::thread_pool> cpu_pool;
    bool rate_limit_enabled = false;
    int rate_limit_limit = 0;
    int rate_limit_window_ms = 0;
    
    bool cache_enabled = false;
    int cache_ttl_sec = 60;
    bool cache_require_full_month_range = true;
    Session(net::ip::tcp::socket&& s, Router& r, bool me, bool al, std::shared_ptr<RedisClient> rc, std::shared_ptr<db::DbPool> dbp)
        : socket(std::move(s)), buffer(), read_timer(socket.get_executor()), router(r), metrics_enabled(me), access_log(al), redis(rc), db(dbp) {}
    void run() { do_read(); }
    void do_read() {
        auto self = shared_from_this();
        
    req = {};
    http_version = 11;
        
        auto parser = std::make_shared<http::request_parser<http::string_body>>();
        
        parser->header_limit(8 * 1024);
        parser->body_limit(1 * 1024 * 1024);

        
        self->read_timer.expires_after(std::chrono::seconds(5));
        self->read_timer.async_wait([self](const boost::system::error_code& ec) {
            if (!ec) {
                
                self->close_socket();
            }
        });

        http::async_read_header(socket, buffer, *parser, [self, parser](beast::error_code ec, std::size_t) {
            
            boost::system::error_code ignored_cancel; self->read_timer.cancel(ignored_cancel);

            if (ec) {
                
                if (ec == http::error::end_of_stream) {
                    self->close_socket();
                    return;
                }

                
                if (ec == http::error::header_limit || ec == beast::http::error::header_limit) {
                    
                    self->reply_json_error(boost::beast::http::status::request_header_fields_too_large, "{\"error\":\"header_too_large\"}", true, "(header)");
                    return;
                }

                
                if (ec == http::error::bad_target || ec == http::error::bad_method || ec == http::error::bad_version ||
                    ec == http::error::bad_field) {
                    self->reply_json_error(boost::beast::http::status::bad_request, "{\"error\":\"bad_request\"}", true, "(parse)");
                    return;
                }

                
                self->close_socket();
                return;
            }

            
            try {
                try { self->http_version = parser->get().version(); } catch(...) {  }
            } catch(...) {}
            
            
            try {
                auto& hdr_req = parser->get();
                std::size_t content_len = 0;
                auto it = hdr_req.find(boost::beast::http::field::content_length);
                if (it != hdr_req.end()) {
                    try { content_len = std::stoul(std::string(it->value())); } catch(...) { content_len = 0; }
                }
                
                
                const std::size_t MAX_PARSER_BODY = 1 * 1024 * 1024;
                if (content_len > MAX_PARSER_BODY) {
                    observability::log_info("oversized_body_header", {{"path", std::string("(header)")}, {"len", int64_t(content_len)}});
                    
                    
                    self->drain_seconds_ = std::min(10, std::max(5, int(content_len / (256 * 1024))));
                    self->reply_json_error(boost::beast::http::status::payload_too_large, "{\"error\":\"body_too_large\"}", true, "(body)");
                    return;
                }
                
                if (content_len == 0) self->read_timer.expires_after(std::chrono::seconds(10));
                else if (content_len <= 128*1024) self->read_timer.expires_after(std::chrono::seconds(20));
                else self->read_timer.expires_after(std::chrono::seconds(60));
                self->read_timer.async_wait([self](const boost::system::error_code& ec) {
                    if (!ec) self->close_socket();
                });
            } catch (...) {
                
                self->close_socket();
                return;
            }

            
            http::async_read(self->socket, self->buffer, *parser, [self, parser](beast::error_code ec2, std::size_t) {
                
                boost::system::error_code ignored_cancel2; self->read_timer.cancel(ignored_cancel2);

                if (ec2) {
                    if (ec2 == http::error::end_of_stream) { self->close_socket(); return; }
                    
                    if (ec2 == http::error::body_limit || ec2 == beast::http::error::body_limit) {
                        self->reply_json_error(boost::beast::http::status::payload_too_large, "{\"error\":\"payload_too_large\"}", true, "(body)");
                        return;
                    }
                    
                    self->close_socket();
                    return;
                }

                
                try {
                    self->req = parser->get();
                } catch (...) {
                    self->close_socket();
                    return;
                }
                self->start_ts = std::chrono::steady_clock::now();
                self->handle_request();
            });
        });
    }
    
    
    
    void handle_request() {
        std::string target = std::string(req.target());
        auto qpos = target.find('?');
        if (qpos != std::string::npos) target.erase(qpos);
        std::string cleaned_target = target;
        auto self = shared_from_this();
        
        try {
            if (std::string(req.method_string()) == "OPTIONS") {
                auto res = std::make_shared<Response>(boost::beast::http::status::no_content, req.version());
                auto it = req.find(boost::beast::http::field::origin);
                if (it != req.end()) res->set("Access-Control-Allow-Origin", std::string(it->value())); else res->set("Access-Control-Allow-Origin", "*");
                res->set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS");
                res->set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With");
                res->set("Access-Control-Allow-Credentials", "true");
                res->keep_alive(req.keep_alive());
                res->prepare_payload();
                send_response(res, cleaned_target);
                return;
            }
        } catch(...) {}
    if (rate_limit_enabled && cleaned_target.rfind("/auth/", 0) == 0 && redis) {
            std::string ip = "unknown";
            try { ip = socket.remote_endpoint().address().to_string(); } catch (...) {}
            if (rate_limit_window_ms <= 0) {
                auto res = std::make_shared<Response>(router.route(req));
                send_response(res, cleaned_target);
                return;
            }
            auto now = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
            int64_t window = now / rate_limit_window_ms;
            std::string key = "rl:" + ip + ":" + std::to_string(window);
            redis->async_incr(key, [self, key, cleaned_target](boost::system::error_code ec, int64_t val) {
                if (ec) {
                    observability::log_warn("redis_unavailable", {{"path", cleaned_target}});

                    auto res = std::make_shared<Response>(self->router.route(self->req));
                    self->send_response(res, cleaned_target);
                    return;
                }
                self->redis->async_pexpire(key, self->rate_limit_window_ms * 2, [self, key, cleaned_target, val](boost::system::error_code ec2, bool) {
                    if (ec2) observability::log_warn("redis_unavailable", {{"path", cleaned_target}});

                    if (val > self->rate_limit_limit) {
                        auto res = std::make_shared<Response>(boost::beast::http::status::too_many_requests, self->req.version());
                        res->set(boost::beast::http::field::content_type, "application/json");
                        res->keep_alive(self->req.keep_alive());
                        res->body() = "{\"error\":\"rate limited\"}";
                        res->prepare_payload();
                        self->send_response(res, cleaned_target);
                        return;
                    }
                    auto res = std::make_shared<Response>(self->router.route(self->req));
                    self->send_response(res, cleaned_target);
                });
            });
            return;
        }
    if (cleaned_target == "/db/health") {
            if (!db) {
                auto res = std::make_shared<Response>(boost::beast::http::status::internal_server_error, req.version());
                res->set(boost::beast::http::field::content_type, "application/json");
                res->keep_alive(req.keep_alive());
                res->body() = "{\"db\":\"down\"}";
                res->prepare_payload();
                send_response(res, cleaned_target);
                return;
            }
            
            auto self = shared_from_this();
            db->async_scalar_int("SELECT 1", [self, cleaned_target](const boost::system::error_code& ec, int v) {
                auto res = std::make_shared<Response>(boost::beast::http::status::ok, self->req.version());
                res->set(boost::beast::http::field::content_type, "application/json");
                res->keep_alive(self->req.keep_alive());
                if (ec || v != 1) {
                    res->result(boost::beast::http::status::internal_server_error);
                    res->body() = "{\"db\":\"down\"}";
                } else {
                    res->body() = "{\"db\":\"ok\"}";
                }
                res->prepare_payload();
                self->send_response(res, cleaned_target);
            });
            return;
        }
        
        if (cleaned_target == "/auth/register" && std::string(req.method_string()) == "POST") {
            
            try {
                
                auto ct = req[boost::beast::http::field::content_type];
                if (ct.find("application/json") == std::string::npos) throw std::runtime_error("bad content type");
                if (req.body().size() > 32 * 1024) throw std::runtime_error("body too large");

                std::string email = json_extract_string(req.body(), "email");
                std::string password = json_extract_string(req.body(), "password");
                
                auto trim = [](std::string s) {
                    size_t a = 0; while (a < s.size() && isspace((unsigned char)s[a])) ++a;
                    size_t b = s.size(); while (b > a && isspace((unsigned char)s[b-1])) --b;
                    return s.substr(a, b-a);
                };
                auto to_lower = [](std::string s){ for (auto &c: s) c = (char)std::tolower((unsigned char)c); return s; };
                email = to_lower(trim(email));
                
                if (email.empty() || password.empty() || password.size() < 8 || password.size() > 1024 || email.size() > 254 || email.find('@') == std::string::npos) {
                    auto res = std::make_shared<Response>(boost::beast::http::status::bad_request, req.version());
                    res->set(boost::beast::http::field::content_type, "application/json");
                    res->keep_alive(req.keep_alive());
                    res->body() = "{\"error\":\"invalid input\"}";
                    res->prepare_payload();
                    send_response(res, cleaned_target);
                    return;
                }
                
                if (!db) {
                    auto res = std::make_shared<Response>(boost::beast::http::status::internal_server_error, req.version());
                    res->set(boost::beast::http::field::content_type, "application/json");
                    res->keep_alive(req.keep_alive());
                    res->body() = "{\"error\":\"db unavailable\"}";
                    res->prepare_payload();
                    send_response(res, cleaned_target);
                    return;
                }
                auto self = shared_from_this();
                db->async_get_user_by_email(email, [self, email, password, cleaned_target](const boost::system::error_code& ec, const db::DbResult& r) {
                    if (ec) {
                        auto res = std::make_shared<Response>(boost::beast::http::status::internal_server_error, self->req.version());
                        res->set(boost::beast::http::field::content_type, "application/json");
                        res->keep_alive(self->req.keep_alive());
                        res->body() = "{\"error\":\"internal\"}";
                        res->prepare_payload();
                        self->send_response(res, cleaned_target);
                        return;
                    }
                    if (r.ok && !r.rows.empty()) {
                        auto res = std::make_shared<Response>(boost::beast::http::status::conflict, self->req.version());
                        res->set(boost::beast::http::field::content_type, "application/json");
                        res->keep_alive(self->req.keep_alive());
                        res->body() = "{\"error\":\"conflict\"}";
                        res->prepare_payload();
                        self->send_response(res, cleaned_target);
                        return;
                    }
                    
                    if (!self->cpu_pool) {
                        
                        boost::asio::post(self->socket.get_executor(), [self, email, cleaned_target]() {
                            auto res = std::make_shared<Response>(boost::beast::http::status::internal_server_error, self->req.version());
                            res->set(boost::beast::http::field::content_type, "application/json");
                            res->keep_alive(self->req.keep_alive());
                            res->body() = "{\"error\":\"internal\"}";
                            res->prepare_payload();
                            self->send_response(res, cleaned_target);
                        });
                    } else {
                        auto cpu_pool = self->cpu_pool;
                        boost::asio::post(*cpu_pool, [self, email, password, cleaned_target]() mutable {
                            std::string hash;
                            try { hash = auth::hash_password(password); } catch (...) { hash = std::string(); }
                            
                            boost::asio::post(self->socket.get_executor(), [self, email, hash, cleaned_target]() {
                                if (hash.empty()) {
                                    auto res = std::make_shared<Response>(boost::beast::http::status::internal_server_error, self->req.version());
                                    res->set(boost::beast::http::field::content_type, "application/json");
                                    res->keep_alive(self->req.keep_alive());
                                    res->body() = "{\"error\":\"internal\"}";
                                    res->prepare_payload();
                                    self->send_response(res, cleaned_target);
                                    return;
                                }
                                self->db->async_insert_user(email, hash, [self, cleaned_target, email](const boost::system::error_code& ec2, const db::DbResult& r2) {
                                    if (ec2) {
                                        auto res = std::make_shared<Response>(boost::beast::http::status::internal_server_error, self->req.version());
                                        res->set(boost::beast::http::field::content_type, "application/json");
                                        res->keep_alive(self->req.keep_alive());
                                        res->body() = "{\"error\":\"internal\"}";
                                        res->prepare_payload();
                                        self->send_response(res, cleaned_target);
                                        return;
                                    }
                                    if (!r2.ok) {
                                        if (r2.sqlstate == "23505") {
                                            auto res = std::make_shared<Response>(boost::beast::http::status::conflict, self->req.version());
                                            res->set(boost::beast::http::field::content_type, "application/json");
                                            res->keep_alive(self->req.keep_alive());
                                            
                                            res->body() = "{\"error\":\"conflict\"}";
                                            res->prepare_payload();
                                            self->send_response(res, cleaned_target);
                                            return;
                                        }
                                        auto res = std::make_shared<Response>(boost::beast::http::status::internal_server_error, self->req.version());
                                        res->set(boost::beast::http::field::content_type, "application/json");
                                        res->keep_alive(self->req.keep_alive());
                                        res->body() = "{\"error\":\"internal\"}";
                                        res->prepare_payload();
                                        self->send_response(res, cleaned_target);
                                        return;
                                    }
                                    
                                    std::string id = "";
                                    if (!r2.rows.empty() && !r2.rows[0].empty() && r2.rows[0][0].has_value()) id = r2.rows[0][0].value();
                                    auto res = std::make_shared<Response>(boost::beast::http::status::created, self->req.version());
                                    res->set(boost::beast::http::field::content_type, "application/json");
                                    res->keep_alive(self->req.keep_alive());
                                    std::string out = std::string("{\"id\":\"") + json_escape_resp(id) + "\",\"email\":\"" + json_escape_resp(email) + "\"}";
                                    res->body() = out;
                                    res->prepare_payload();
                                    self->send_response(res, cleaned_target);
                                });
                            });
                        });
                    }
                });
            } catch (...) {
                auto res = std::make_shared<Response>(boost::beast::http::status::bad_request, req.version());
                res->set(boost::beast::http::field::content_type, "application/json");
                res->keep_alive(req.keep_alive());
                res->body() = "{\"error\":\"invalid input\"}";
                res->prepare_payload();
                send_response(res, cleaned_target);
            }
            return;
        }

        
        if (cleaned_target == "/calendars" && std::string(req.method_string()) == "POST") {
            
            auto claims_opt = Session::authenticate_bearer(req, self->jwt_secret);
            if (!claims_opt) {
                auto res = std::make_shared<Response>(boost::beast::http::status::unauthorized, req.version());
                res->set(boost::beast::http::field::content_type, "application/json");
                res->keep_alive(req.keep_alive());
                res->body() = "{\"error\":\"unauthorized\"}";
                res->prepare_payload();
                send_response(res, cleaned_target);
                return;
            }
            auto cl = *claims_opt;
            try {
                auto ct = req[boost::beast::http::field::content_type];
                if (ct.find("application/json") == std::string::npos) throw std::runtime_error("bad content type");
                if (req.body().size() > 16*1024) throw std::runtime_error("body too large");
                std::string title = json_extract_string(req.body(), "title");
                if (title.empty() || title.size() > 1024) {
                    auto res = std::make_shared<Response>(boost::beast::http::status::bad_request, req.version());
                    res->set(boost::beast::http::field::content_type, "application/json");
                    res->keep_alive(req.keep_alive());
                    res->body() = "{\"error\":\"invalid input\"}";
                    res->prepare_payload();
                    send_response(res, cleaned_target);
                    return;
                }
                auto self = shared_from_this();
                self->db->async_create_calendar(cl.sub, title, [self, cleaned_target](const boost::system::error_code& ec, const db::DbResult& r) {
                    if (ec || !r.ok || r.rows.empty()) {
                        auto res = std::make_shared<Response>(boost::beast::http::status::internal_server_error, self->req.version());
                        res->set(boost::beast::http::field::content_type, "application/json");
                        res->keep_alive(self->req.keep_alive());
                        res->body() = "{\"error\":\"internal\"}";
                        res->prepare_payload();
                        self->send_response(res, cleaned_target);
                        return;
                    }
                    std::string cal_id = r.rows[0][0].has_value() ? r.rows[0][0].value() : std::string();
                    auto res = std::make_shared<Response>(boost::beast::http::status::created, self->req.version());
                    res->set(boost::beast::http::field::content_type, "application/json");
                    res->keep_alive(self->req.keep_alive());
                    res->body() = std::string("{\"id\":\"") + json_escape_resp(cal_id) + "\"}";
                    res->prepare_payload();
                    self->send_response(res, cleaned_target);
                });
            } catch (...) {
                auto res = std::make_shared<Response>(boost::beast::http::status::bad_request, req.version());
                res->set(boost::beast::http::field::content_type, "application/json");
                res->keep_alive(req.keep_alive());
                res->body() = "{\"error\":\"invalid input\"}";
                res->prepare_payload();
                send_response(res, cleaned_target);
            }
            return;
        }

        
        if (cleaned_target.rfind("/recurrence/", 0) == 0) {
            
            std::string tail = cleaned_target.substr(std::string("/recurrence/").size());
            size_t slash = tail.find('/');
            std::string rule_id = (slash == std::string::npos) ? tail : tail.substr(0, slash);
            std::string sub = (slash == std::string::npos) ? std::string() : tail.substr(slash+1);

            
            if (sub == "exdates" && std::string(req.method_string()) == "POST") {
                auto claims_opt = Session::authenticate_bearer(req, self->jwt_secret);
                if (!claims_opt) { auto res = std::make_shared<Response>(boost::beast::http::status::unauthorized, req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(req.keep_alive()); res->body() = "{\"error\":\"unauthorized\"}"; res->prepare_payload(); send_response(res, cleaned_target); return; }
                auto cl = *claims_opt; auto self = shared_from_this();
                try {
                    auto ct = self->req[boost::beast::http::field::content_type]; if (ct.find("application/json") == std::string::npos) throw std::runtime_error("bad content type"); if (self->req.body().size() > 8*1024) throw std::runtime_error("body too large");
                    std::string date = json_extract_string(self->req.body(), "date"); if (date.empty()) { auto res = std::make_shared<Response>(boost::beast::http::status::bad_request, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = "{\"error\":\"invalid input\"}"; res->prepare_payload(); self->send_response(res, cleaned_target); return; }
                    
                    std::string sql = "SELECT e.calendar_id FROM recurrence_rules rr JOIN events e ON e.id=rr.event_id WHERE rr.id=$1 LIMIT 1";
                    self->db->async_exec_params(sql, std::vector<std::string>{rule_id}, [self, cleaned_target, cl, rule_id, date](const boost::system::error_code& ec2, const db::DbResult& r2) {
                        if (ec2 || !r2.ok || r2.rows.empty() || !r2.rows[0][0].has_value()) { auto res = std::make_shared<Response>(boost::beast::http::status::not_found, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = "{\"error\":\"not found\"}"; res->prepare_payload(); self->send_response(res, cleaned_target); return; }
                        std::string calid = r2.rows[0][0].value();
                        
                        self->db->async_get_membership(calid, cl.sub, [self, cleaned_target, rule_id, date, calid](const boost::system::error_code& ec3, const db::DbResult& r3) {
                            if (ec3 || !r3.ok || r3.rows.empty()) { auto res = std::make_shared<Response>(boost::beast::http::status::forbidden, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = "{\"error\":\"forbidden\"}"; res->prepare_payload(); self->send_response(res, cleaned_target); return; }
                            int role = 0; if (r3.rows[0][2].has_value()) { auto parsed = json_parse_int32_strict(r3.rows[0][2]); if (!parsed.has_value()) { auto res = std::make_shared<Response>(boost::beast::http::status::forbidden, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = "{\"error\":\"forbidden\"}"; res->prepare_payload(); self->send_response(res, cleaned_target); return; } role = *parsed; }
                            if (role < 1) { auto res = std::make_shared<Response>(boost::beast::http::status::forbidden, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = "{\"error\":\"forbidden\"}"; res->prepare_payload(); self->send_response(res, cleaned_target); return; }
                            
                            self->db->async_add_recurrence_exdate(rule_id, date, [self, cleaned_target, rule_id, date, calid](const boost::system::error_code& ec4, const db::DbResult& r4) {
                                if (ec4) { auto res = std::make_shared<Response>(boost::beast::http::status::internal_server_error, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = "{\"error\":\"internal\"}"; res->prepare_payload(); self->send_response(res, cleaned_target); return; }
                                auto p = month_range_utc_from_ts(date);
                                if (p.first.empty()) { auto res = std::make_shared<Response>(boost::beast::http::status::bad_request, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = "{\"error\":\"invalid date\"}"; res->prepare_payload(); self->send_response(res, cleaned_target); return; }
                                std::string range_start = p.first; std::string range_end = p.second;
                                
                                try {
                                    if (self->redis && self->cache_enabled) {
                                        std::string yyyymm = p.first.substr(0,4) + p.first.substr(5,2);
                                        std::string key = std::string("ev:") + calid + ":" + yyyymm;
                                        self->redis->async_del(key, [](boost::system::error_code, int64_t){});
                                    }
                                } catch(...) {}
                                std::string payload = std::string("{\"rule_id\":\"") + json_escape_resp(rule_id) + "\",\"calendar_id\":\"" + json_escape_resp(calid) + "\",\"range_start\":\"" + json_escape_resp(range_start) + "\",\"range_end\":\"" + json_escape_resp(range_end) + "\"}";
                                self->db->async_enqueue_outbox_job("recompute_rule", payload, "", [self, cleaned_target](const boost::system::error_code& ec5, const db::DbResult& r5) {
                                    if (ec5 || !r5.ok) { auto res = std::make_shared<Response>(boost::beast::http::status::internal_server_error, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = "{\"error\":\"internal\"}"; res->prepare_payload(); self->send_response(res, cleaned_target); return; }
                                    auto res = std::make_shared<Response>(boost::beast::http::status::ok, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = "{\"status\":\"ok\"}"; res->prepare_payload(); self->send_response(res, cleaned_target);
                                });
                            });
                        });
                    });
                } catch (...) { auto res = std::make_shared<Response>(boost::beast::http::status::bad_request, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = "{\"error\":\"invalid input\"}"; res->prepare_payload(); self->send_response(res, cleaned_target); return; }
                return;
            }

            
            if (sub == "exdates" && std::string(req.method_string()) == "DELETE") {
                auto claims_opt = Session::authenticate_bearer(req, self->jwt_secret);
                if (!claims_opt) { auto res = std::make_shared<Response>(boost::beast::http::status::unauthorized, req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(req.keep_alive()); res->body() = "{\"error\":\"unauthorized\"}"; res->prepare_payload(); send_response(res, cleaned_target); return; }
                auto cl = *claims_opt; auto self = shared_from_this();
                try {
                    auto ct = self->req[boost::beast::http::field::content_type]; if (ct.find("application/json") == std::string::npos) throw std::runtime_error("bad content type"); if (self->req.body().size() > 8*1024) throw std::runtime_error("body too large");
                    std::string date = json_extract_string(self->req.body(), "date"); if (date.empty()) { auto res = std::make_shared<Response>(boost::beast::http::status::bad_request, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = "{\"error\":\"invalid input\"}"; res->prepare_payload(); self->send_response(res, cleaned_target); return; }
                    std::string sql = "SELECT e.calendar_id FROM recurrence_rules rr JOIN events e ON e.id=rr.event_id WHERE rr.id=$1 LIMIT 1";
                    self->db->async_exec_params(sql, std::vector<std::string>{rule_id}, [self, cleaned_target, cl, rule_id, date](const boost::system::error_code& ec2, const db::DbResult& r2) {
                        if (ec2 || !r2.ok || r2.rows.empty() || !r2.rows[0][0].has_value()) { auto res = std::make_shared<Response>(boost::beast::http::status::not_found, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = "{\"error\":\"not found\"}"; res->prepare_payload(); self->send_response(res, cleaned_target); return; }
                        std::string calid = r2.rows[0][0].value();
                        self->db->async_get_membership(calid, cl.sub, [self, cleaned_target, rule_id, date, calid](const boost::system::error_code& ec3, const db::DbResult& r3) {
                            if (ec3 || !r3.ok || r3.rows.empty()) { auto res = std::make_shared<Response>(boost::beast::http::status::forbidden, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = "{\"error\":\"forbidden\"}"; res->prepare_payload(); self->send_response(res, cleaned_target); return; }
                            int role = 0; if (r3.rows[0][2].has_value()) { auto parsed = json_parse_int32_strict(r3.rows[0][2]); if (!parsed.has_value()) { auto res = std::make_shared<Response>(boost::beast::http::status::forbidden, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = "{\"error\":\"forbidden\"}"; res->prepare_payload(); self->send_response(res, cleaned_target); return; } role = *parsed; }
                            if (role < 1) { auto res = std::make_shared<Response>(boost::beast::http::status::forbidden, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = "{\"error\":\"forbidden\"}"; res->prepare_payload(); self->send_response(res, cleaned_target); return; }
                            self->db->async_remove_recurrence_exdate(rule_id, date, [self, cleaned_target, rule_id, date, calid](const boost::system::error_code& ec4, const db::DbResult& r4) {
                                if (ec4) { auto res = std::make_shared<Response>(boost::beast::http::status::internal_server_error, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = "{\"error\":\"internal\"}"; res->prepare_payload(); self->send_response(res, cleaned_target); return; }
                                auto p = month_range_utc_from_ts(date);
                                if (p.first.empty()) { auto res = std::make_shared<Response>(boost::beast::http::status::bad_request, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = "{\"error\":\"invalid date\"}"; res->prepare_payload(); self->send_response(res, cleaned_target); return; }
                                std::string range_start = p.first; std::string range_end = p.second;
                                
                                try {
                                    if (self->redis && self->cache_enabled) {
                                        std::string yyyymm = p.first.substr(0,4) + p.first.substr(5,2);
                                        std::string key = std::string("ev:") + calid + ":" + yyyymm;
                                        self->redis->async_del(key, [](boost::system::error_code, int64_t){});
                                    }
                                } catch(...) {}
                                std::string payload = std::string("{\"rule_id\":\"") + json_escape_resp(rule_id) + "\",\"calendar_id\":\"" + json_escape_resp(calid) + "\",\"range_start\":\"" + json_escape_resp(range_start) + "\",\"range_end\":\"" + json_escape_resp(range_end) + "\"}";
                                self->db->async_enqueue_outbox_job("recompute_rule", payload, "", [self, cleaned_target](const boost::system::error_code& ec5, const db::DbResult& r5) {
                                    if (ec5 || !r5.ok) { auto res = std::make_shared<Response>(boost::beast::http::status::internal_server_error, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = "{\"error\":\"internal\"}"; res->prepare_payload(); self->send_response(res, cleaned_target); return; }
                                    auto res = std::make_shared<Response>(boost::beast::http::status::ok, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = "{\"status\":\"ok\"}"; res->prepare_payload(); self->send_response(res, cleaned_target);
                                });
                            });
                        });
                    });
                } catch (...) { auto res = std::make_shared<Response>(boost::beast::http::status::bad_request, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = "{\"error\":\"invalid input\"}"; res->prepare_payload(); self->send_response(res, cleaned_target); return; }
                return;
            }

            
            if (sub == "occurrence" && std::string(req.method_string()) == "PATCH") {
                auto claims_opt = Session::authenticate_bearer(req, self->jwt_secret);
                if (!claims_opt) { auto res = std::make_shared<Response>(boost::beast::http::status::unauthorized, req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(req.keep_alive()); res->body() = "{\"error\":\"unauthorized\"}"; res->prepare_payload(); send_response(res, cleaned_target); return; }
                auto cl = *claims_opt; auto self = shared_from_this();
                try {
                    auto ct = self->req[boost::beast::http::field::content_type]; if (ct.find("application/json") == std::string::npos) throw std::runtime_error("bad content type"); if (self->req.body().size() > 16*1024) throw std::runtime_error("body too large");
                    std::string original = json_extract_string(self->req.body(), "original_start_ts"); if (original.empty()) { auto res = std::make_shared<Response>(boost::beast::http::status::bad_request, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = "{\"error\":\"invalid input\"}"; res->prepare_payload(); self->send_response(res, cleaned_target); return; }
                    auto new_start_pair = json_extract_string_opt_present(self->req.body(), "new_start_ts"); auto new_end_pair = json_extract_string_opt_present(self->req.body(), "new_end_ts"); auto title_pair = json_extract_string_opt_present(self->req.body(), "title"); auto notes_pair = json_extract_string_opt_present(self->req.body(), "notes");
                    
                    bool cancelled = false; auto cancelled_pair = json_extract_int_opt(self->req.body(), "cancelled"); if (cancelled_pair.has_value()) cancelled = (*cancelled_pair != 0);
                    std::optional<std::string> new_start = new_start_pair.first ? std::optional<std::string>(new_start_pair.second) : std::nullopt;
                    std::optional<std::string> new_end = new_end_pair.first ? std::optional<std::string>(new_end_pair.second) : std::nullopt;
                    std::optional<std::string> title = title_pair.first ? std::optional<std::string>(title_pair.second) : std::nullopt;
                    std::optional<std::string> notes = notes_pair.first ? std::optional<std::string>(notes_pair.second) : std::nullopt;
            
            {
                std::string sql = "SELECT e.calendar_id FROM recurrence_rules rr JOIN events e ON e.id=rr.event_id WHERE rr.id=$1 LIMIT 1";
                self->db->async_exec_params(sql, std::vector<std::string>{rule_id}, [self, cleaned_target, rule_id, original, new_start, new_end, title, notes, cancelled, cl](const boost::system::error_code& ec0, const db::DbResult& r0) {
                    if (ec0 || !r0.ok || r0.rows.empty() || !r0.rows[0][0].has_value()) { auto res = std::make_shared<Response>(boost::beast::http::status::not_found, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = "{\"error\":\"not found\"}"; res->prepare_payload(); self->send_response(res, cleaned_target); return; }
                    std::string calid = r0.rows[0][0].value();
                    
                    self->db->async_get_membership(calid, cl.sub, [self, cleaned_target, rule_id, original, new_start, new_end, title, notes, cancelled, calid, cl](const boost::system::error_code& ecm, const db::DbResult& rm) {
                        if (ecm || !rm.ok || rm.rows.empty()) { auto res = std::make_shared<Response>(boost::beast::http::status::forbidden, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = "{\"error\":\"forbidden\"}"; res->prepare_payload(); self->send_response(res, cleaned_target); return; }
                        int role = 0; if (rm.rows[0][2].has_value()) { auto parsed = json_parse_int32_strict(rm.rows[0][2]); if (!parsed.has_value()) { auto res = std::make_shared<Response>(boost::beast::http::status::forbidden, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = "{\"error\":\"forbidden\"}"; res->prepare_payload(); self->send_response(res, cleaned_target); return; } role = *parsed; }
                        if (role < 1) { auto res = std::make_shared<Response>(boost::beast::http::status::forbidden, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = "{\"error\":\"forbidden\"}"; res->prepare_payload(); self->send_response(res, cleaned_target); return; }

                        
                        self->db->async_upsert_occurrence_override(rule_id, original, new_start, new_end, title, notes, cancelled, [self, cleaned_target, rule_id, calid, original, new_start](const boost::system::error_code& ec2, const db::DbResult& r2) {
                            if (ec2 == boost::asio::error::invalid_argument) { auto res = std::make_shared<Response>(boost::beast::http::status::bad_request, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = "{\"error\":\"invalid timestamp format\"}"; res->prepare_payload(); self->send_response(res, cleaned_target); return; }
                            if (ec2) { auto res = std::make_shared<Response>(boost::beast::http::status::internal_server_error, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = "{\"error\":\"internal\"}"; res->prepare_payload(); self->send_response(res, cleaned_target); return; }

                            
                            auto p1 = month_range_utc_from_ts(original);
                            if (p1.first.empty()) { auto res = std::make_shared<Response>(boost::beast::http::status::bad_request, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = "{\"error\":\"invalid original timestamp\"}"; res->prepare_payload(); self->send_response(res, cleaned_target); return; }
                            auto ranges = std::make_shared<std::vector<std::pair<std::string,std::string>>>(); ranges->push_back(p1);
                            if (new_start.has_value()) {
                                auto p2 = month_range_utc_from_ts(new_start.value()); if (!p2.first.empty() && p2.first != p1.first) ranges->push_back(p2);
                            }

                            
                            try {
                                if (self->redis && self->cache_enabled) {
                                    for (const auto &r : *ranges) {
                                        std::string yyyymm = r.first.substr(0,4) + r.first.substr(5,2);
                                        std::string key = std::string("ev:") + calid + ":" + yyyymm;
                                        self->redis->async_del(key, [](boost::system::error_code, int64_t){});
                                    }
                                }
                            } catch(...) {}

                            auto enqueue_next = std::make_shared<std::function<void(size_t)>>();
                            *enqueue_next = [self, cleaned_target, rule_id, calid, ranges, enqueue_next](size_t idx) {
                                if (idx >= ranges->size()) {
                                    auto res = std::make_shared<Response>(boost::beast::http::status::ok, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = "{\"status\":\"ok\"}"; res->prepare_payload(); self->send_response(res, cleaned_target); return;
                                }
                                const auto&r = (*ranges)[idx];
                                std::string payload = std::string("{\"rule_id\":\"") + json_escape_resp(rule_id) + "\",\"calendar_id\":\"" + json_escape_resp(calid) + "\",\"range_start\":\"" + json_escape_resp(r.first) + "\",\"range_end\":\"" + json_escape_resp(r.second) + "\"}";
                                self->db->async_enqueue_outbox_job("recompute_rule", payload, "", [self, cleaned_target, enqueue_next, idx](const boost::system::error_code& ec3, const db::DbResult& r3) {
                                    if (ec3 || !r3.ok) { auto res = std::make_shared<Response>(boost::beast::http::status::internal_server_error, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = "{\"error\":\"internal\"}"; res->prepare_payload(); self->send_response(res, cleaned_target); return; }
                                    (*enqueue_next)(idx+1);
                                });
                            };
                            (*enqueue_next)(0);
                        });
                    });
                });
            }
                } catch (...) { auto res = std::make_shared<Response>(boost::beast::http::status::bad_request, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = "{\"error\":\"invalid input\"}"; res->prepare_payload(); self->send_response(res, cleaned_target); return; }
                return;
            }

            
            if (sub.empty() && std::string(req.method_string()) == "PATCH") {
                auto claims_opt = Session::authenticate_bearer(req, self->jwt_secret);
                if (!claims_opt) { auto res = std::make_shared<Response>(boost::beast::http::status::unauthorized, req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(req.keep_alive()); res->body() = "{\"error\":\"unauthorized\"}"; res->prepare_payload(); send_response(res, cleaned_target); return; }
                auto cl = *claims_opt; auto self = shared_from_this();
                try {
                    auto ct = self->req[boost::beast::http::field::content_type]; if (ct.find("application/json") == std::string::npos) throw std::runtime_error("bad content type"); if (self->req.body().size() > 16*1024) throw std::runtime_error("body too large");
                    
                    auto freq_pair = json_extract_string_opt_present(self->req.body(), "freq"); auto interval_pair = json_extract_int_present(self->req.body(), "interval"); auto count_pair = json_extract_int_present(self->req.body(), "count"); auto until_pair = json_extract_string_opt_present(self->req.body(), "until_ts");
                    std::string freq = (freq_pair.first && freq_pair.second.has_value()) ? freq_pair.second.value() : std::string(); std::optional<int> interval_opt = interval_pair.first ? std::optional<int>(interval_pair.second) : std::nullopt; std::optional<int> count_opt = count_pair.first ? std::optional<int>(count_pair.second) : std::nullopt; std::optional<std::string> until_opt = (until_pair.first && until_pair.second.has_value()) ? std::optional<std::string>(until_pair.second.value()) : std::nullopt;
                    
                    std::vector<std::string> params;
                    params.push_back(rule_id); 
                    int idx = 2;
                    std::string set_sql;
                    if (freq_pair.first) { if (!set_sql.empty()) set_sql += ", "; set_sql += "freq = $" + std::to_string(idx); params.push_back(freq_pair.second.has_value() ? freq_pair.second.value() : std::string()); ++idx; }
                    if (interval_pair.first) { if (!set_sql.empty()) set_sql += ", "; set_sql += "interval = $" + std::to_string(idx); params.push_back(std::to_string(interval_pair.second)); ++idx; }
                    if (count_pair.first) { if (!set_sql.empty()) set_sql += ", "; set_sql += "count = $" + std::to_string(idx); params.push_back(std::to_string(count_pair.second)); ++idx; }
                    if (until_pair.first) { if (!set_sql.empty()) set_sql += ", "; set_sql += "until_ts = NULLIF($" + std::to_string(idx) + ", '')::timestamptz"; params.push_back(until_pair.second.has_value() ? until_pair.second.value() : std::string()); ++idx; }
                    
                    if (set_sql.empty()) {
                        auto res = std::make_shared<Response>(boost::beast::http::status::bad_request, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = "{\"error\":\"no fields to update\"}"; res->prepare_payload(); self->send_response(res, cleaned_target); return;
                    }

                    
                    std::string meta_sql = "SELECT e.calendar_id, e.start_ts FROM recurrence_rules rr JOIN events e ON e.id=rr.event_id WHERE rr.id=$1 LIMIT 1";
                    self->db->async_exec_params(meta_sql, std::vector<std::string>{rule_id}, [self, cleaned_target, params, idx, set_sql, rule_id, cl](const boost::system::error_code& ec_meta, const db::DbResult& r_meta) mutable {
                        if (ec_meta || !r_meta.ok || r_meta.rows.empty() || !r_meta.rows[0][0].has_value()) {
                            auto res = std::make_shared<Response>(boost::beast::http::status::not_found, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = "{\"error\":\"not found\"}"; res->prepare_payload(); self->send_response(res, cleaned_target); return;
                        }
                        std::string calid = r_meta.rows[0][0].value(); std::string start_ts = r_meta.rows[0][1].has_value() ? r_meta.rows[0][1].value() : std::string();

                        
                        self->db->async_get_membership(calid, cl.sub, [self, cleaned_target, params, set_sql, rule_id, calid, start_ts](const boost::system::error_code& ecm, const db::DbResult& rm) mutable {
                            if (ecm || !rm.ok || rm.rows.empty()) { auto res = std::make_shared<Response>(boost::beast::http::status::forbidden, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = "{\"error\":\"forbidden\"}"; res->prepare_payload(); self->send_response(res, cleaned_target); return; }
                            int role = 0; if (rm.rows[0][2].has_value()) { auto parsed = json_parse_int32_strict(rm.rows[0][2]); if (!parsed.has_value()) { auto res = std::make_shared<Response>(boost::beast::http::status::forbidden, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = "{\"error\":\"forbidden\"}"; res->prepare_payload(); self->send_response(res, cleaned_target); return; } role = *parsed; }
                            if (role < 1) { auto res = std::make_shared<Response>(boost::beast::http::status::forbidden, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = "{\"error\":\"forbidden\"}"; res->prepare_payload(); self->send_response(res, cleaned_target); return; }

                            
                            auto p1 = month_range_utc_from_ts(start_ts);
                            if (p1.first.empty()) {
                                
                                time_t nowt = std::time(nullptr);
                                struct tm tmv; gmtime_r(&nowt, &tmv);
                                char buf[32]; char buf2[32];
                                std::snprintf(buf, sizeof(buf), "%04d-%02d-01T00:00:00Z", tmv.tm_year+1900, tmv.tm_mon+1);
                                int ny = tmv.tm_year+1900; int nm = tmv.tm_mon+2; if (nm==13) { nm=1; ny++; }
                                std::snprintf(buf2, sizeof(buf2), "%04d-%02d-01T00:00:00Z", ny, nm);
                                p1 = {std::string(buf), std::string(buf2)};
                            }

                            
                            std::string payload = std::string("{\"rule_id\":\"") + json_escape_resp(rule_id) + "\",\"calendar_id\":\"" + json_escape_resp(calid) + "\",\"range_start\":\"" + json_escape_resp(p1.first) + "\",\"range_end\":\"" + json_escape_resp(p1.second) + "\"}";
                            
                            auto local_params = params; local_params.push_back(payload);
                            
                            std::string sql = "WITH upd AS (UPDATE recurrence_rules SET " + set_sql + " WHERE id = $1 RETURNING id) INSERT INTO outbox_jobs(job_type, payload) SELECT 'recompute_rule', $" + std::to_string((int)local_params.size()) + "::jsonb FROM upd RETURNING id";
                            self->db->async_exec_params(sql, local_params, [self, cleaned_target, calid, p1](const boost::system::error_code& ec2, const db::DbResult& r2) {
                                if (ec2 == boost::asio::error::invalid_argument) { auto res = std::make_shared<Response>(boost::beast::http::status::bad_request, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = "{\"error\":\"invalid timestamp format\"}"; res->prepare_payload(); self->send_response(res, cleaned_target); return; }
                                if (ec2 || !r2.ok) { auto res = std::make_shared<Response>(boost::beast::http::status::internal_server_error, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = "{\"error\":\"internal\"}"; res->prepare_payload(); self->send_response(res, cleaned_target); return; }
                                
                                try {
                                    if (self->redis && self->cache_enabled) {
                                        
                                        if (!p1.first.empty()) {
                                            std::string yyyymm = p1.first.substr(0,4) + p1.first.substr(5,2);
                                            std::string key = std::string("ev:") + calid + ":" + yyyymm;
                                            self->redis->async_del(key, [](boost::system::error_code, int64_t){});
                                        }
                                        
                                        if (!p1.second.empty()) {
                                            std::string yyyymm2 = p1.second.substr(0,4) + p1.second.substr(5,2);
                                            std::string key2 = std::string("ev:") + calid + ":" + yyyymm2;
                                            self->redis->async_del(key2, [](boost::system::error_code, int64_t){});
                                        }
                                    }
                                } catch(...) {}
                                auto res = std::make_shared<Response>(boost::beast::http::status::ok, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = "{\"status\":\"ok\"}"; res->prepare_payload(); self->send_response(res, cleaned_target);
                            });
                        });
                    });
                } catch(...) { auto res = std::make_shared<Response>(boost::beast::http::status::bad_request, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = "{\"error\":\"invalid input\"}"; res->prepare_payload(); self->send_response(res, cleaned_target); return; }
                return;
            }
        }

        if (cleaned_target == "/calendars" && std::string(req.method_string()) == "GET") {
            
            auto claims_opt = Session::authenticate_bearer(req, self->jwt_secret);
            if (!claims_opt) {
                auto res = std::make_shared<Response>(boost::beast::http::status::unauthorized, req.version());
                res->set(boost::beast::http::field::content_type, "application/json");
                res->keep_alive(req.keep_alive());
                res->body() = "{\"error\":\"unauthorized\"}";
                res->prepare_payload();
                send_response(res, cleaned_target);
                return;
            }
            auto cl = *claims_opt;
            auto self = shared_from_this();
            self->db->async_list_calendars_for_user(cl.sub, [self, cleaned_target](const boost::system::error_code& ec, const db::DbResult& r) {
                if (ec || !r.ok) {
                    auto res = std::make_shared<Response>(boost::beast::http::status::internal_server_error, self->req.version());
                    res->set(boost::beast::http::field::content_type, "application/json");
                    res->keep_alive(self->req.keep_alive());
                    res->body() = "{\"error\":\"internal\"}";
                    res->prepare_payload();
                    self->send_response(res, cleaned_target);
                    return;
                }
                
                auto s = [](const std::optional<std::string>& o){ return o.has_value() ? o.value() : std::string(); };
                std::string out = "[";
                for (size_t i = 0; i < r.rows.size(); ++i) {
                    const auto& row = r.rows[i];
                    if (i) out += ",";
                    
                    out += std::string("{\"id\":\"") + json_escape_resp(s(row[0])) + "\",\"title\":\"" + json_escape_resp(s(row[1])) + "\",\"owner\":\"" + json_escape_resp(s(row[2])) + "\",\"role\":" + json_emit_int(row[3], 0) + "}";
                }
                out += "]";
                auto res = std::make_shared<Response>(boost::beast::http::status::ok, self->req.version());
                res->set(boost::beast::http::field::content_type, "application/json");
                res->keep_alive(self->req.keep_alive());
                res->body() = out;
                res->prepare_payload();
                self->send_response(res, cleaned_target);
            });
            return;
        }

        
        if (cleaned_target.rfind("/calendars/", 0) == 0) {
            std::string id_part = cleaned_target.substr(std::string("/calendars/").size());
            
            size_t slash = id_part.find('/');
            std::string calid = (slash == std::string::npos) ? id_part : id_part.substr(0, slash);

            
            if (slash == std::string::npos && std::string(req.method_string()) == "GET") {
                auto claims_opt = Session::authenticate_bearer(req, self->jwt_secret);
                if (!claims_opt) { auto res = std::make_shared<Response>(boost::beast::http::status::unauthorized, req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(req.keep_alive()); res->body() = "{\"error\":\"unauthorized\"}"; res->prepare_payload(); send_response(res, cleaned_target); return; }
                auto cl = *claims_opt;
                auto self = shared_from_this();
                
                self->db->async_get_membership(calid, cl.sub, [self, cleaned_target, calid](const boost::system::error_code& ec, const db::DbResult& r) {
                    if (ec || !r.ok || r.rows.empty()) { auto res = std::make_shared<Response>(boost::beast::http::status::forbidden, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = "{\"error\":\"forbidden\"}"; res->prepare_payload(); self->send_response(res, cleaned_target); return; }
                    
                    self->db->async_get_calendar(calid, [self, cleaned_target](const boost::system::error_code& ec2, const db::DbResult& r2) {
                        if (ec2 || !r2.ok || r2.rows.empty()) { auto res = std::make_shared<Response>(boost::beast::http::status::not_found, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = "{\"error\":\"not found\"}"; res->prepare_payload(); self->send_response(res, cleaned_target); return; }
                        const auto& row = r2.rows[0];
                        auto s = [](const std::optional<std::string>& o){ return o.has_value() ? o.value() : std::string(); };
                        std::string out = std::string("{\"id\":\"") + json_escape_resp(s(row[0])) + "\",\"title\":\"" + json_escape_resp(s(row[1])) + "\",\"owner\":\"" + json_escape_resp(s(row[2])) + "\"}";
                        auto res = std::make_shared<Response>(boost::beast::http::status::ok, self->req.version());
                        res->set(boost::beast::http::field::content_type, "application/json");
                        res->keep_alive(self->req.keep_alive());
                        res->body() = out;
                        res->prepare_payload();
                        self->send_response(res, cleaned_target);
                    });
                });
                return;
            }

            
            if (slash == std::string::npos && std::string(req.method_string()) == "PATCH") {
                auto claims_opt = Session::authenticate_bearer(req, self->jwt_secret);
                if (!claims_opt) { auto res = std::make_shared<Response>(boost::beast::http::status::unauthorized, req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(req.keep_alive()); res->body() = "{\"error\":\"unauthorized\"}"; res->prepare_payload(); send_response(res, cleaned_target); return; }
                auto cl = *claims_opt;
                auto self = shared_from_this();
                
                self->db->async_get_membership(calid, cl.sub, [self, cleaned_target, calid](const boost::system::error_code& ec, const db::DbResult& r) {
                    if (ec || !r.ok || r.rows.empty()) { auto res = std::make_shared<Response>(boost::beast::http::status::forbidden, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = "{\"error\":\"forbidden\"}"; res->prepare_payload(); self->send_response(res, cleaned_target); return; }
                    int actor_role = 0;
                        if (r.rows[0][2].has_value()) {
                            auto parsed = json_parse_int32_strict(r.rows[0][2]);
                            if (!parsed.has_value()) { auto res = std::make_shared<Response>(boost::beast::http::status::forbidden, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = "{\"error\":\"forbidden\"}"; res->prepare_payload(); self->send_response(res, cleaned_target); return; }
                            actor_role = *parsed;
                        }
                        if (actor_role < 1) { auto res = std::make_shared<Response>(boost::beast::http::status::forbidden, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = "{\"error\":\"forbidden\"}"; res->prepare_payload(); self->send_response(res, cleaned_target); return; }
                    
                    try {
                        auto ct = self->req[boost::beast::http::field::content_type];
                        if (ct.find("application/json") == std::string::npos) throw std::runtime_error("bad content type");
                        std::string title = json_extract_string(self->req.body(), "title");
                        if (title.empty()) { auto res = std::make_shared<Response>(boost::beast::http::status::bad_request, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = "{\"error\":\"invalid input\"}"; res->prepare_payload(); self->send_response(res, cleaned_target); return; }
                        const std::string sql = "UPDATE calendars SET title=$2 WHERE id=$1 RETURNING id, title, owner_user_id";
                        self->db->async_exec_params(sql, std::vector<std::string>{calid, title}, [self, cleaned_target](const boost::system::error_code& ec2, const db::DbResult& r2) {
                            if (ec2 || !r2.ok || r2.rows.empty()) { auto res = std::make_shared<Response>(boost::beast::http::status::internal_server_error, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = "{\"error\":\"internal\"}"; res->prepare_payload(); self->send_response(res, cleaned_target); return; }
                            const auto& row = r2.rows[0];
                            auto s = [](const std::optional<std::string>& o){ return o.has_value() ? o.value() : std::string(); };
                            std::string out = std::string("{\"id\":\"") + json_escape_resp(s(row[0])) + "\",\"title\":\"" + json_escape_resp(s(row[1])) + "\",\"owner\":\"" + json_escape_resp(s(row[2])) + "\"}";
                            auto res = std::make_shared<Response>(boost::beast::http::status::ok, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = out; res->prepare_payload(); self->send_response(res, cleaned_target);
                        });
                    } catch (...) {
                        auto res = std::make_shared<Response>(boost::beast::http::status::bad_request, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = "{\"error\":\"invalid input\"}"; res->prepare_payload(); self->send_response(res, cleaned_target); return;
                    }
                });
                return;
            }

            
            if (slash == std::string::npos && std::string(req.method_string()) == "DELETE") {
                auto claims_opt = Session::authenticate_bearer(req, self->jwt_secret);
                if (!claims_opt) { auto res = std::make_shared<Response>(boost::beast::http::status::unauthorized, req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(req.keep_alive()); res->body() = "{\"error\":\"unauthorized\"}"; res->prepare_payload(); send_response(res, cleaned_target); return; }
                auto cl = *claims_opt;
                auto self = shared_from_this();
                    self->db->async_get_calendar(calid, [self, cleaned_target, cl, calid](const boost::system::error_code& ec, const db::DbResult& r) {
                    if (ec || !r.ok || r.rows.empty()) { auto res = std::make_shared<Response>(boost::beast::http::status::not_found, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = "{\"error\":\"not found\"}"; res->prepare_payload(); self->send_response(res, cleaned_target); return; }
                    std::string owner = r.rows[0][2].has_value() ? r.rows[0][2].value() : std::string();
                    if (owner != cl.sub) { auto res = std::make_shared<Response>(boost::beast::http::status::forbidden, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = "{\"error\":\"forbidden\"}"; res->prepare_payload(); self->send_response(res, cleaned_target); return; }
                    
                    const std::string sql = "DELETE FROM calendars WHERE id=$1";
                    self->db->async_exec_params(sql, std::vector<std::string>{calid}, [self, cleaned_target](const boost::system::error_code& ec2, const db::DbResult& r2) {
                        if (ec2 || !r2.ok) { auto res = std::make_shared<Response>(boost::beast::http::status::internal_server_error, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = "{\"error\":\"internal\"}"; res->prepare_payload(); self->send_response(res, cleaned_target); return; }
                        auto res = std::make_shared<Response>(boost::beast::http::status::no_content, self->req.version()); res->keep_alive(self->req.keep_alive()); res->prepare_payload(); self->send_response(res, cleaned_target);
                    });
                });
                return;
            }

            
            if (slash != std::string::npos) {
                std::string sub = id_part.substr(slash+1);
                    
                    
                    if (sub.rfind("members/", 0) == 0 && std::string(req.method_string()) == "DELETE") {
                        auto claims_opt = Session::authenticate_bearer(req, self->jwt_secret);
                        if (!claims_opt) { auto res = std::make_shared<Response>(boost::beast::http::status::unauthorized, req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(req.keep_alive()); res->body() = "{\"error\":\"unauthorized\"}"; res->prepare_payload(); send_response(res, cleaned_target); return; }
                        auto cl = *claims_opt;
                        auto self = shared_from_this();
                        
                        std::string target_user_id = std::string(sub.substr(std::string("members/").size()));
                        if (target_user_id.empty()) { auto res = std::make_shared<Response>(boost::beast::http::status::bad_request, req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(req.keep_alive()); res->body() = "{\"error\":\"invalid input\"}"; res->prepare_payload(); send_response(res, cleaned_target); return; }
                        
                        try { observability::log_info("remove_member_attempt", {{"actor_id", cl.sub}, {"calendar_id", calid}, {"target_user_id", target_user_id}}); } catch(...) {}
                        self->db->async_get_membership(calid, cl.sub, [self, cleaned_target, calid, cl, target_user_id](const boost::system::error_code& ec, const db::DbResult& r) {
                            if (ec || !r.ok || r.rows.empty()) { auto res = std::make_shared<Response>(boost::beast::http::status::forbidden, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = "{\"error\":\"forbidden\"}"; res->prepare_payload(); self->send_response(res, cleaned_target); return; }
                            auto actor_role_opt = parse_role_from_membership_row(r);
                            if (!actor_role_opt.has_value()) { auto res = std::make_shared<Response>(boost::beast::http::status::forbidden, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = "{\"error\":\"forbidden\"}"; res->prepare_payload(); self->send_response(res, cleaned_target); return; }
                            int actor_role = *actor_role_opt;

                            
                            if (cl.sub == target_user_id) {
                                try { observability::log_warn("rbac_forbidden_remove_member", {{"actor_id", cl.sub}, {"calendar_id", calid}, {"actor_role", int64_t(actor_role)}, {"target_user_id", target_user_id}, {"target_role", int64_t(actor_role)}, {"reason", std::string("self_remove")}}); } catch(...) {}
                                auto res = std::make_shared<Response>(boost::beast::http::status::bad_request, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = "{\"error\":\"forbidden_self_remove\"}"; res->prepare_payload(); self->send_response(res, cleaned_target); return; }

                            
                            try { observability::log_info("remove_member_fetch_target", {{"actor_id", cl.sub}, {"calendar_id", calid}, {"target_user_id", target_user_id}, {"actor_role", int64_t(actor_role)}}); } catch(...) {}
                            self->db->async_get_membership(calid, target_user_id, [self, cleaned_target, calid, cl, target_user_id, actor_role](const boost::system::error_code& ec2, const db::DbResult& r2) {
                                if (ec2) { auto res = std::make_shared<Response>(boost::beast::http::status::internal_server_error, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = "{\"error\":\"internal\"}"; res->prepare_payload(); self->send_response(res, cleaned_target); return; }
                                if (!r2.ok || r2.rows.empty()) { try { observability::log_warn("rbac_forbidden_remove_member", {{"actor_id", cl.sub}, {"calendar_id", calid}, {"actor_role", int64_t(actor_role)}, {"target_user_id", target_user_id}, {"target_role", int64_t(-1)}, {"reason", std::string("not_member")}}); } catch(...) {} auto res = std::make_shared<Response>(boost::beast::http::status::not_found, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = "{\"error\":\"not_found\"}"; res->prepare_payload(); self->send_response(res, cleaned_target); return; }
                                auto target_role_opt = parse_role_from_membership_row(r2);
                                if (!target_role_opt.has_value()) { auto res = std::make_shared<Response>(boost::beast::http::status::bad_request, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = "{\"error\":\"invalid_membership\"}"; res->prepare_payload(); self->send_response(res, cleaned_target); return; }
                                int target_role = *target_role_opt;

                                
                                if (target_role == 2) {
                                    try { observability::log_warn("rbac_forbidden_remove_member", {{"actor_id", cl.sub}, {"calendar_id", calid}, {"actor_role", int64_t(actor_role)}, {"target_user_id", target_user_id}, {"target_role", int64_t(target_role)}, {"reason", std::string("remove_owner")}}); } catch(...) {}
                                    auto res = std::make_shared<Response>(boost::beast::http::status::bad_request, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = "{\"error\":\"cannot_remove_owner\"}"; res->prepare_payload(); self->send_response(res, cleaned_target); return; }

                                bool allowed = false;
                                if (actor_role == 2) {
                                    
                                    allowed = (target_role == 0 || target_role == 1);
                                } else if (actor_role == 1) {
                                    
                                    allowed = (target_role == 0);
                                } else {
                                    allowed = false;
                                }
                                if (!allowed) {
                                    try { observability::log_warn("rbac_forbidden_remove_member", {{"actor_id", cl.sub}, {"calendar_id", calid}, {"actor_role", int64_t(actor_role)}, {"target_user_id", target_user_id}, {"target_role", int64_t(target_role)}, {"reason", std::string("rbac_denied")}}); } catch(...) {}
                                    auto res = std::make_shared<Response>(boost::beast::http::status::forbidden, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = "{\"error\":\"forbidden\",\"message\":\"not allowed to remove target\"}"; res->prepare_payload(); self->send_response(res, cleaned_target); return; }

                                try { observability::log_info("remove_member_allowed", {{"actor_id", cl.sub}, {"calendar_id", calid}, {"target_user_id", target_user_id}, {"target_role", int64_t(target_role)}}); } catch(...) {}
                                
                                self->db->async_remove_membership(calid, target_user_id, [self, cleaned_target](const boost::system::error_code& ec3, const db::DbResult& r3) {
                                    if (ec3 || !r3.ok) { auto res = std::make_shared<Response>(boost::beast::http::status::internal_server_error, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = "{\"error\":\"internal\"}"; res->prepare_payload(); self->send_response(res, cleaned_target); return; }
                                    auto res = std::make_shared<Response>(boost::beast::http::status::no_content, self->req.version()); res->keep_alive(self->req.keep_alive()); res->prepare_payload(); self->send_response(res, cleaned_target);
                                });
                            });
                        });
                        return;
                    }
                
                if (sub == "share" && std::string(req.method_string()) == "POST") {
                    auto claims_opt = Session::authenticate_bearer(req, self->jwt_secret);
                    if (!claims_opt) { auto res = std::make_shared<Response>(boost::beast::http::status::unauthorized, req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(req.keep_alive()); res->body() = "{\"error\":\"unauthorized\"}"; res->prepare_payload(); send_response(res, cleaned_target); return; }
                    auto cl = *claims_opt;
                    auto self = shared_from_this();
                    
                    self->db->async_get_membership(calid, cl.sub, [self, cleaned_target, calid, cl](const boost::system::error_code& ec, const db::DbResult& r) {
                        if (ec || !r.ok || r.rows.empty()) { auto res = std::make_shared<Response>(boost::beast::http::status::forbidden, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = "{\"error\":\"forbidden\"}"; res->prepare_payload(); self->send_response(res, cleaned_target); return; }
                        int role = 0;
                        if (r.rows[0][2].has_value()) {
                            auto parsed = json_parse_int32_strict(r.rows[0][2]);
                            if (!parsed.has_value()) { auto res = std::make_shared<Response>(boost::beast::http::status::forbidden, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = "{\"error\":\"forbidden\"}"; res->prepare_payload(); self->send_response(res, cleaned_target); return; }
                            role = *parsed;
                        }
                        if (role < 1) { auto res = std::make_shared<Response>(boost::beast::http::status::forbidden, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = "{\"error\":\"forbidden\"}"; res->prepare_payload(); self->send_response(res, cleaned_target); return; }
                        try {
                            auto ct = self->req[boost::beast::http::field::content_type];
                            if (ct.find("application/json") == std::string::npos) throw std::runtime_error("bad content type");
                            std::string email = json_extract_string(self->req.body(), "email");
                            auto role_opt = json_extract_int_opt(self->req.body(), "role");
                            if (email.empty()) { auto res = std::make_shared<Response>(boost::beast::http::status::bad_request, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = "{\"error\":\"invalid input\"}"; res->prepare_payload(); self->send_response(res, cleaned_target); return; }
                            
                            int requested_role = role_opt.has_value() ? static_cast<int>(role_opt.value()) : 0;
                            
                            if (!is_valid_role_value(requested_role)) {
                                auto res = std::make_shared<Response>(boost::beast::http::status::bad_request, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = "{\"error\":\"invalid_role\"}"; res->prepare_payload(); self->send_response(res, cleaned_target); return; }
                            
                            if (requested_role == 2) {
                                auto res = std::make_shared<Response>(boost::beast::http::status::bad_request, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = "{\"error\":\"invalid_role\"}"; res->prepare_payload(); self->send_response(res, cleaned_target); return; }

                            
                            if (role < 2 && requested_role >= 1) {
                                try { observability::log_warn("rbac_forbidden_assign", {{"actor_id", cl.sub}, {"calendar_id", calid}, {"requested_role", int64_t(requested_role)}, {"actor_role", int64_t(role)}, {"target_email", email}}); } catch(...) {}
                                auto res = std::make_shared<Response>(boost::beast::http::status::forbidden, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = "{\"error\":\"forbidden\",\"message\":\"only owner can assign moderator role\"}"; res->prepare_payload(); self->send_response(res, cleaned_target); return; }
                            
                            self->db->async_get_user_by_email(email, [self, cleaned_target, calid, requested_role, cl](const boost::system::error_code& ec2, const db::DbResult& r2) {
                                if (ec2 || !r2.ok || r2.rows.empty()) { auto res = std::make_shared<Response>(boost::beast::http::status::not_found, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = "{\"error\":\"not found\"}"; res->prepare_payload(); self->send_response(res, cleaned_target); return; }
                                std::string user_id = r2.rows[0][0].has_value() ? r2.rows[0][0].value() : std::string();
                                
                                self->db->async_get_membership(calid, user_id, [self, cleaned_target, calid, user_id, requested_role, cl](const boost::system::error_code& ec3, const db::DbResult& r3) {
                                    if (ec3) { auto res = std::make_shared<Response>(boost::beast::http::status::internal_server_error, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = "{\"error\":\"internal\"}"; res->prepare_payload(); self->send_response(res, cleaned_target); return; }
                                    if (r3.ok && !r3.rows.empty()) {
                                        
                                        self->db->async_update_membership_role(calid, user_id, static_cast<int>(requested_role), [self, cleaned_target, cl](const boost::system::error_code& ec4, const db::DbResult& r4) {
                                            if (ec4 || !r4.ok) { auto res = std::make_shared<Response>(boost::beast::http::status::internal_server_error, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = "{\"error\":\"internal\"}"; res->prepare_payload(); self->send_response(res, cleaned_target); return; }
                                            auto res = std::make_shared<Response>(boost::beast::http::status::ok, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = "{\"status\":\"ok\"}"; res->prepare_payload(); self->send_response(res, cleaned_target);
                                        });
                                        return;
                                    }
                                    
                                    self->db->async_add_membership(calid, user_id, static_cast<int>(requested_role), [self, cleaned_target, cl](const boost::system::error_code& ec4, const db::DbResult& r4) {
                                        if (ec4 || !r4.ok) { auto res = std::make_shared<Response>(boost::beast::http::status::internal_server_error, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = "{\"error\":\"internal\"}"; res->prepare_payload(); self->send_response(res, cleaned_target); return; }
                                        auto res = std::make_shared<Response>(boost::beast::http::status::created, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = "{\"status\":\"ok\"}"; res->prepare_payload(); self->send_response(res, cleaned_target);
                                    });
                                });
                            });
                        } catch (...) { auto res = std::make_shared<Response>(boost::beast::http::status::bad_request, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = "{\"error\":\"invalid input\"}"; res->prepare_payload(); self->send_response(res, cleaned_target); return; }
                    });
                    return;
                }

                
                if (sub == "events") {
                    
                    if (std::string(req.method_string()) == "POST") {
                        auto claims_opt = Session::authenticate_bearer(req, self->jwt_secret);
                        if (!claims_opt) { auto res = std::make_shared<Response>(boost::beast::http::status::unauthorized, req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(req.keep_alive()); res->body() = "{\"error\":\"unauthorized\"}"; res->prepare_payload(); send_response(res, cleaned_target); return; }
                        auto cl = *claims_opt;
                        auto self = shared_from_this();
                        self->db->async_get_membership(calid, cl.sub, [self, cleaned_target, calid, cl](const boost::system::error_code& ec, const db::DbResult& r) {
                            if (ec || !r.ok || r.rows.empty()) { auto res = std::make_shared<Response>(boost::beast::http::status::forbidden, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = "{\"error\":\"forbidden\"}"; res->prepare_payload(); self->send_response(res, cleaned_target); return; }
                            int role = 0; if (r.rows[0][2].has_value()) {
                                auto parsed = json_parse_int32_strict(r.rows[0][2]);
                                if (!parsed.has_value()) { auto res = std::make_shared<Response>(boost::beast::http::status::forbidden, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = "{\"error\":\"forbidden\"}"; res->prepare_payload(); self->send_response(res, cleaned_target); return; }
                                role = *parsed;
                            }
                            if (role < 1) { auto res = std::make_shared<Response>(boost::beast::http::status::forbidden, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = "{\"error\":\"forbidden\"}"; res->prepare_payload(); self->send_response(res, cleaned_target); return; }
                            try {
                                auto ct = self->req[boost::beast::http::field::content_type]; if (ct.find("application/json") == std::string::npos) throw std::runtime_error("bad content type"); if (self->req.body().size() > 16*1024) throw std::runtime_error("body too large");
                                std::string title = json_extract_string(self->req.body(), "title");
                                auto desc_opt_pair = json_extract_string_opt_present(self->req.body(), "description");
                                auto start = json_extract_string(self->req.body(), "start_ts");
                                auto end_opt_pair = json_extract_string_opt_present(self->req.body(), "end_ts");
                                if (title.empty() || start.empty()) { auto res = std::make_shared<Response>(boost::beast::http::status::bad_request, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = "{\"error\":\"invalid input\"}"; res->prepare_payload(); self->send_response(res, cleaned_target); return; }
                                
                                
                                std::optional<std::string> desc_opt = desc_opt_pair.first ? desc_opt_pair.second : std::nullopt;
                                std::optional<std::string> end_opt = end_opt_pair.first ? end_opt_pair.second : std::nullopt;
                                
                                std::string body = self->req.body();
                                auto find_recurrence_object = [&](const std::string& src)->std::string{
                                    size_t p = src.find("\"recurrence\"");
                                    if (p == std::string::npos) return std::string();
                                    size_t brace = src.find('{', p);
                                    if (brace == std::string::npos) return std::string();
                                    size_t i = brace; int depth = 0;
                                    for (; i < src.size(); ++i) {
                                        if (src[i] == '{') ++depth;
                                        else if (src[i] == '}') { --depth; if (depth == 0) { return src.substr(brace, i - brace + 1); } }
                                    }
                                    return std::string();
                                };
                                std::string rec_js = find_recurrence_object(body);

                                auto s = [](const std::optional<std::string>& o){ return o.has_value() ? o.value() : std::string(); };
                                if (rec_js.empty()) {
                                    
                                    self->db->async_create_event_with_occurrence(calid, cl.sub, title, desc_opt, start, end_opt, [self, cleaned_target, s, calid, start](const boost::system::error_code& ec_ins, const db::DbResult& r_ins) {
                                            if (ec_ins == boost::asio::error::invalid_argument) {
                                                auto res = std::make_shared<Response>(boost::beast::http::status::bad_request, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = "{\"error\":\"invalid timestamp format\"}"; res->prepare_payload(); self->send_response(res, cleaned_target); return;
                                            }
                                            if (ec_ins || !r_ins.ok || r_ins.rows.empty()) {
                                                auto res = std::make_shared<Response>(boost::beast::http::status::internal_server_error, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = "{\"error\":\"internal\"}"; res->prepare_payload(); self->send_response(res, cleaned_target); return;
                                            }
                                        const auto& row = r_ins.rows[0];
                                        std::string out = build_created_event_json(row);
                                        auto res = std::make_shared<Response>(boost::beast::http::status::created, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = out;
                                        
                                        try { observability::log_info("created_response_out", {{"ctx","create_event_nonrec"}, {"sample", out.substr(0, std::min<size_t>(out.size(), 200))}}); } catch(...) {}
                                        
                                        try {
                                            
                                            json_extract_string(out, "id");
                                        } catch (const std::exception &e) {
                                            try { observability::log_error("created_response_invalid_json", {{"ctx","create_event_nonrec"}, {"err", std::string(e.what())}, {"sample", out.substr(0, std::min<size_t>(out.size(), 200))}}); } catch(...) {}
                                        }
                                        res->prepare_payload(); self->send_response(res, cleaned_target);
                                        
                                        try {
                                            if (self->redis && self->cache_enabled) {
                                                auto p = month_range_utc_from_ts(start);
                                                if (!p.first.empty()) {
                                                    std::string yyyymm = p.first.substr(0,4) + p.first.substr(5,2);
                                                    std::string key = std::string("ev:") + calid + ":" + yyyymm;
                                                    self->redis->async_del(key, [](boost::system::error_code, int64_t){});
                                                }
                                            }
                                        } catch(...) {}
                                    });
                                } else {
                                    
                                    recurrence::Rule rule;
                                    std::string freq = json_extract_string(rec_js, "freq"); if (!freq.empty()) rule.freq = freq;
                                    auto interval_pair = json_extract_int_present(rec_js, "interval"); if (interval_pair.first) rule.interval = interval_pair.second > 0 ? interval_pair.second : 1;
                                    auto count_pair = json_extract_int_present(rec_js, "count"); if (count_pair.first && count_pair.second > 0) rule.count = count_pair.second;
                                    std::string until = json_extract_string(rec_js, "until_ts"); if (!until.empty()) rule.until_ts = until;
                                    
                                    size_t bypos = rec_js.find("byweekday");
                                    if (bypos != std::string::npos) {
                                        size_t lb = rec_js.find('[', bypos);
                                        size_t rb = rec_js.find(']', bypos);
                                        if (lb != std::string::npos && rb != std::string::npos && rb > lb) {
                                            std::string inner = rec_js.substr(lb+1, rb-lb-1);
                                            std::vector<int> v; size_t p = 0;
                                                while (p < inner.size()) {
                                                    while (p < inner.size() && !isdigit((unsigned char)inner[p]) && inner[p] != '-') ++p;
                                                    if (p>=inner.size()) break;
                                                    size_t q = p; if (inner[q] == '-') ++q; while (q < inner.size() && isdigit((unsigned char)inner[q])) ++q;
                                                    auto parsed = parse_int_strict_sv(std::string_view(inner).substr(p, q - p));
                                                    if (parsed && *parsed >= 0 && *parsed <= 6) v.push_back(*parsed);
                                                    p = q;
                                                }
                                            if (!v.empty()) rule.byweekday = v;
                                        }
                                    }
                                    if (rule.freq == "DAILY" || rule.freq == "WEEKLY") {
                                        time_t nowt = std::time(nullptr);
                                        
                                        
                                        
                                        
                                        int64_t MAX_ALLOWED_OCCURRENCES = 10000;
                                        try {
                                            const char* envv = std::getenv("MAX_OCCURRENCES_PER_RULE");
                                            if (envv) MAX_ALLOWED_OCCURRENCES = std::stoll(envv);
                                        } catch(...) { MAX_ALLOWED_OCCURRENCES = 10000; }
                                        time_t window_to = nowt + 31LL*24*60*60; 
                                        auto base_start_opt = recurrence::parse_iso_z(start);
                                        if (rule.count.has_value()) {
                                            int64_t cnt = static_cast<int64_t>(rule.count.value());
                                            if (cnt > MAX_ALLOWED_OCCURRENCES) {
                                                try { observability::log_warn("recurrence_count_exceeds_limit", {{"count", std::to_string(cnt)}, {"max_allowed", std::to_string(MAX_ALLOWED_OCCURRENCES)}}); } catch(...) {}
                                                auto res = std::make_shared<Response>(boost::beast::http::status::payload_too_large, self->req.version());
                                                res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive());
                                                res->body() = "{\"error\":\"count_too_large\",\"message\":\"recurrence count exceeds allowed limit\"}";
                                                res->prepare_payload(); self->send_response(res, cleaned_target); return;
                                            }
                                            int64_t interval = rule.interval < 1 ? 1 : rule.interval;
                                            if (base_start_opt) {
                                                
                                                int64_t span_seconds = 0;
                                                if (rule.freq == "DAILY") span_seconds = cnt * interval * 24LL*60*60 + 24LL*60*60; 
                                                else  span_seconds = cnt * interval * 7LL*24*60*60 + 24LL*60*60; 
                                                
                                                if (span_seconds < 0) span_seconds = 31LL*24*60*60;
                                                window_to = *base_start_opt + span_seconds;
                                                try { observability::log_info("materialize_window_computed", {{"reason","count"}, {"count", std::to_string(cnt)}, {"window_to", recurrence::format_iso_z(window_to)}}); } catch(...) {}
                                            } else {
                                                
                                                window_to = nowt + 31LL*24*60*60;
                                            }
                                        } else if (rule.until_ts.has_value()) {
                                            auto until_opt = recurrence::parse_iso_z(rule.until_ts.value());
                                            if (until_opt) {
                                                window_to = *until_opt;
                                                try { observability::log_info("materialize_window_computed", {{"reason","until_ts"}, {"window_to", recurrence::format_iso_z(window_to)}}); } catch(...) {}
                                            }
                                        }
                                        
                                        if (window_to <= nowt) window_to = nowt + 31LL*24*60*60;
                                        
                                        time_t window_from = nowt;
                                        if (base_start_opt) window_from = *base_start_opt;
                                        auto occs = recurrence::materialize_occurrences(start, end_opt, rule, window_from, window_to);
                                        try { observability::log_info("materialize_generated", {{"count", std::to_string((int)occs.size())}, {"max_allowed", std::to_string(MAX_ALLOWED_OCCURRENCES)}}); } catch(...) {}
                                        if ((int64_t)occs.size() > MAX_ALLOWED_OCCURRENCES) {
                                            try { observability::log_warn("materialize_exceeds_limit", {{"generated", std::to_string((int)occs.size())}, {"max_allowed", std::to_string(MAX_ALLOWED_OCCURRENCES)}}); } catch(...) {}
                                            auto res = std::make_shared<Response>(boost::beast::http::status::payload_too_large, self->req.version());
                                            res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive());
                                            res->body() = "{\"error\":\"count_too_large\",\"message\":\"recurrence would materialize too many occurrences\"}";
                                            res->prepare_payload(); self->send_response(res, cleaned_target); return;
                                        }
                                        std::vector<std::string> starts; starts.reserve(occs.size());
                                        std::vector<std::string> ends; ends.reserve(occs.size());
                                        for (const auto &p : occs) { starts.push_back(p.first); ends.push_back(p.second.has_value() ? p.second.value() : std::string()); }
                                        
                                        self->db->async_create_event_with_recurrence(calid, cl.sub, title, desc_opt, start, end_opt, rule.freq, rule.interval, rule.count, rule.until_ts, rule.byweekday, starts, ends, [self, cleaned_target, calid, start](const boost::system::error_code& ec3, const db::DbResult& r3) {
                                            if (ec3 == boost::asio::error::invalid_argument) { auto res = std::make_shared<Response>(boost::beast::http::status::bad_request, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = "{\"error\":\"invalid timestamp format\"}"; res->prepare_payload(); self->send_response(res, cleaned_target); return; }
                                            if (ec3 || !r3.ok || r3.rows.empty()) { auto res = std::make_shared<Response>(boost::beast::http::status::internal_server_error, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = "{\"error\":\"internal\"}"; res->prepare_payload(); self->send_response(res, cleaned_target); return; }
                                            const auto& row = r3.rows[0];
                                            std::string out = build_created_event_json(row);
                                            auto res = std::make_shared<Response>(boost::beast::http::status::created, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = out;
                                            
                                            try { observability::log_info("created_response_out", {{"ctx","create_event_recurr"}, {"sample", out.substr(0, std::min<size_t>(out.size(), 200))}}); } catch(...) {}
                                            
                                            try {
                                                json_extract_string(out, "id");
                                            } catch (const std::exception &e) {
                                                try { observability::log_error("created_response_invalid_json", {{"ctx","create_event_recurr"}, {"err", std::string(e.what())}, {"sample", out.substr(0, std::min<size_t>(out.size(), 200))}}); } catch(...) {}
                                            }
                                            res->prepare_payload(); self->send_response(res, cleaned_target);
                                            
                                            try {
                                                if (self->redis && self->cache_enabled) {
                                                    auto months = months_touched(start, std::nullopt);
                                                    if (!months.empty()) {
                                                        
                                                        auto timer = std::make_shared<boost::asio::steady_timer>(self->socket.get_executor());
                                                        timer->expires_after(std::chrono::milliseconds(50));
                                                        auto pending = std::make_shared<std::atomic<int>>(months.size());
                                                        auto any_err = std::make_shared<std::atomic<bool>>(false);
                                                        for (const auto &ym : months) {
                                                            std::string key = std::string("ev:") + calid + ":" + ym;
                                                            self->redis->async_del(key, [timer, pending, any_err, key](boost::system::error_code ec, int64_t) {
                                                                if (ec) { any_err->store(true); observability::log_warn("cache_invalidate_error", {{"key", key}, {"err", int64_t(ec.value())}}); }
                                                                else observability::log_info("cache_invalidate_ok", {{"key", key}});
                                                                if (pending->fetch_sub(1) == 1) {
                                                                    boost::system::error_code ig; timer->cancel(ig);
                                                                }
                                                            });
                                                        }
                                                        
                                                        timer->async_wait([timer](const boost::system::error_code &ec) {
                                                            if (!ec) observability::log_info("cache_invalidate_deadline_fired", {});
                                                        });
                                                    }
                                                }
                                            } catch(...) {}
                                        });
                                    } else {
                                        
                                        auto res = std::make_shared<Response>(boost::beast::http::status::bad_request, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = "{\"error\":\"unsupported recurrence\"}"; res->prepare_payload(); self->send_response(res, cleaned_target);
                                    }
                                }
                            } catch (...) { auto res = std::make_shared<Response>(boost::beast::http::status::bad_request, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = "{\"error\":\"invalid input\"}"; res->prepare_payload(); self->send_response(res, cleaned_target); return; }
                        });
                        return;
                    }
                    
                    if (std::string(req.method_string()) == "GET") {
                        auto claims_opt = Session::authenticate_bearer(req, self->jwt_secret);
                        if (!claims_opt) { auto res = std::make_shared<Response>(boost::beast::http::status::unauthorized, req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(req.keep_alive()); res->body() = "{\"error\":\"unauthorized\"}"; res->prepare_payload(); send_response(res, cleaned_target); return; }
                        auto cl = *claims_opt; auto self = shared_from_this();
                        
                        self->db->async_get_membership(calid, cl.sub, [self, cleaned_target, calid](const boost::system::error_code& ec, const db::DbResult& r) {
                            if (ec || !r.ok || r.rows.empty()) { auto res = std::make_shared<Response>(boost::beast::http::status::forbidden, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = "{\"error\":\"forbidden\"}"; res->prepare_payload(); self->send_response(res, cleaned_target); return; }
                            
                            std::string qs = std::string(self->req.target()); auto qpos = qs.find('?'); std::string from, to; if (qpos != std::string::npos) {
                                std::string q = qs.substr(qpos+1);
                                
                                auto find_q = [&](const std::string& key)->std::string{
                                    std::string k = key + "=";
                                    size_t p = q.find(k); if (p == std::string::npos) return std::string(); size_t v = p + k.size(); size_t e = q.find('&', v); if (e==std::string::npos) e=q.size(); return q.substr(v, e-v);
                                };
                                from = url_decode(find_q("from")); to = url_decode(find_q("to"));
                            }
                            if (from.empty() || to.empty()) { auto res = std::make_shared<Response>(boost::beast::http::status::bad_request, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = "{\"error\":\"missing range\"}"; res->prepare_payload(); self->send_response(res, cleaned_target); return; }

                            
                            bool tried_cache = false;
                            if (self->cache_enabled && self->redis) {
                                auto mr = month_range_utc_from_ts(from);
                                if (!mr.first.empty() && from == mr.first && to == mr.second) {
                                    std::string yyyymm = std::string(from.substr(0,4)) + std::string(from.substr(5,2));
                                    std::string key = std::string("ev:") + calid + ":" + yyyymm;
                                    tried_cache = true;
                                    
                                    self->redis->async_get(key, [self, key, calid, from, to, cleaned_target](boost::system::error_code ec_cache, std::optional<std::string> val) {
                                        if (ec_cache) {
                                            observability::log_warn("redis_get_error", {{"key", key}, {"err", int64_t(ec_cache.value())}});
                                            
                                        } else if (val.has_value()) {
                                            
                                            auto body = val.value();
                                            auto res = std::make_shared<Response>(boost::beast::http::status::ok, self->req.version());
                                            res->set(boost::beast::http::field::content_type, "application/json");
                                            res->set("X-Cache", "hit");
                                            res->set("X-Cache-Key", key);
                                            res->keep_alive(self->req.keep_alive());
                                            res->body() = body; res->prepare_payload(); self->send_response(res, cleaned_target);
                                            observability::log_info("cache_get", {{"key", key}, {"result", std::string("hit")}});
                                            observability::log_info("cache_set_metric", {{"op", std::string("get")}, {"result", std::string("hit")}});
                                            return;
                                        }

                                        
                                        static std::mutex inflight_mutex;
                                        static std::unordered_map<std::string, std::vector<std::function<void(const std::string&, bool)>>> inflight_map;

                                        bool leader = false;
                                        {
                                            std::lock_guard<std::mutex> g(inflight_mutex);
                                            auto it = inflight_map.find(key);
                                            if (it != inflight_map.end()) {
                                                
                                                it->second.emplace_back([self, cleaned_target, key](const std::string& out, bool set_ok){
                                                    auto r = std::make_shared<Response>(boost::beast::http::status::ok, self->req.version());
                                                    r->set(boost::beast::http::field::content_type, "application/json");
                                                    r->set("X-Cache", set_ok ? "miss" : "error");
                                                    r->set("X-Cache-Key", key);
                                                    r->keep_alive(self->req.keep_alive()); r->body() = out; r->prepare_payload(); self->send_response(r, cleaned_target);
                                                });
                                            } else {
                                                
                                                inflight_map.emplace(key, std::vector<std::function<void(const std::string&, bool)>>());
                                                leader = true;
                                            }
                                        }

                                        if (!leader) {
                                            
                                            return;
                                        }

                                        
                                        self->db->async_list_occurrences(calid, from, to, [self, cleaned_target, key](const boost::system::error_code& ec2, const db::DbResult& r2) {
                                            if (ec2 == boost::asio::error::invalid_argument) {
                                                auto res = std::make_shared<Response>(boost::beast::http::status::bad_request, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = "{\"error\":\"invalid timestamp format\"}"; res->prepare_payload(); self->send_response(res, cleaned_target);
                                                
                                                std::lock_guard<std::mutex> g(inflight_mutex);
                                                inflight_map.erase(key);
                                                return;
                                            }
                                            if (ec2 || !r2.ok) {
                                                auto res = std::make_shared<Response>(boost::beast::http::status::internal_server_error, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = "{\"error\":\"internal\"}"; res->prepare_payload(); self->send_response(res, cleaned_target);
                                                std::lock_guard<std::mutex> g(inflight_mutex);
                                                inflight_map.erase(key);
                                                return;
                                            }
                                            std::string items = "[";
                                            for (size_t i=0;i<r2.rows.size();++i){ if (i) items += ","; const auto& row = r2.rows[i]; auto s = [](const std::optional<std::string>& o){ return o.has_value() ? o.value() : std::string(); };
                                                
                                                
                                                
                                                
                                                if (row.size() >= 9) {
                                                    items += std::string("{\"id\":\"") + json_escape_resp(s(row[0])) + "\",";
                                                    items += std::string("\"event_id\":\"") + json_escape_resp(s(row[1])) + "\",";
                                                    items += std::string("\"recurrence_rule_id\":") + (row[2].has_value() ? (std::string("\"") + json_escape_resp(s(row[2])) + std::string("\"")) : std::string("null")) + ",";
                                                    items += std::string("\"title\":\"") + json_escape_resp(s(row[3])) + "\",";
                                                    items += std::string("\"description\":") + (row[4].has_value() ? (std::string("\"") + json_escape_resp(row[4].value()) + std::string("\"")) : std::string("null")) + ",";
                                                    items += std::string("\"start_ts\":\"") + json_escape_resp(normalize_iso_z(s(row[5]))) + "\",";
                                                    items += std::string("\"end_ts\":") + (row[6].has_value() ? (std::string("\"") + json_escape_resp(normalize_iso_z(s(row[6]))) + std::string("\"")) : std::string("null")) + ",";
                                                    items += std::string("\"created_by\":\"") + json_escape_resp(s(row[7])) + "\",";
                                                    items += std::string("\"created_at\":\"") + json_escape_resp(s(row[8])) + "\"";
                                                    items += std::string("}");
                                                } else {
                                                    items += std::string("{\"id\":\"") + json_escape_resp(s(row[0])) + "\"," + "\"title\":\"" + json_escape_resp(s(row[1])) + "\",";
                                                    items += std::string("\"description\":") + (row[2].has_value() ? (std::string("\"") + json_escape_resp(row[2].value()) + std::string("\"")) : std::string("null"));
                                                    items += std::string(",\"start_ts\":\"") + json_escape_resp(normalize_iso_z(s(row[3]))) + "\"";
                                                    items += std::string(",\"end_ts\":") + (row[4].has_value()
                                                        ? (std::string("\"") + json_escape_resp(normalize_iso_z(s(row[4]))) + "\"")
                                                        : std::string("null"));
                                                    items += std::string(",\"created_by\":\"") + json_escape_resp(s(row[5])) + "\"";
                                                    items += std::string(",\"created_at\":\"") + json_escape_resp(s(row[6])) + "\"";
                                                    items += std::string("}");
                                                }

                                            }
                                            items += "]";
                                            std::string out = std::string("{\"items\":") + items + "}";

                                            
                                            auto leader_res = std::make_shared<Response>(boost::beast::http::status::ok, self->req.version());
                                            leader_res->set(boost::beast::http::field::content_type, "application/json");
                                            leader_res->set("X-Cache-Key", key);
                                            leader_res->keep_alive(self->req.keep_alive()); leader_res->body() = out; leader_res->prepare_payload();

                                            
                                            auto timer = std::make_shared<boost::asio::steady_timer>(self->socket.get_executor());
                                            timer->expires_after(std::chrono::milliseconds(50));
                                            auto sent = std::make_shared<bool>(false);

                                                
                                            self->redis->async_setex(key, self->cache_ttl_sec, out, [self, key, leader_res, sent, timer, out](boost::system::error_code ec_set, bool ok) {
                                                if (ec_set) observability::log_warn("redis_set_error", {{"key", key}, {"err", int64_t(ec_set.value())}});
                                                else observability::log_info("redis_set_ok", {{"key", key}});
                                                
                                                boost::system::error_code ig;
                                                timer->cancel(ig);
                                                if (!*sent) {
                                                    *sent = true;
                                                    leader_res->set("X-Cache", ec_set ? "error" : "miss");
                                                    self->send_response(leader_res, std::string("(cache)") );
                                                }
                                                
                                                std::vector<std::function<void(const std::string&, bool)>> waiters;
                                                {
                                                    std::lock_guard<std::mutex> g(inflight_mutex);
                                                    auto it = inflight_map.find(key);
                                                    if (it != inflight_map.end()) waiters = std::move(it->second);
                                                    inflight_map.erase(key);
                                                }
                                                for (auto &w : waiters) {
                                                    try { w(out, ec_set==boost::system::error_code()); } catch(...) {}
                                                }
                                            });

                            
                        timer->async_wait([self, leader_res, sent, key](const boost::system::error_code& tec) {
                                                if (tec) return; 
                                                if (!*sent) {
                                                    *sent = true;
                                                    leader_res->set("X-Cache", "miss");
                                                    self->send_response(leader_res, std::string("(cache)") );
                                                    observability::log_info("cache_set_deadline_fired", {{"key", key}});
                                                }
                                            });
                                        });
                                    });
                                    return;
                                }
                            }

                            
                            if (!tried_cache) {
                                self->db->async_list_occurrences(calid, from, to, [self, cleaned_target](const boost::system::error_code& ec2, const db::DbResult& r2) {
                                    if (ec2 == boost::asio::error::invalid_argument) { auto res = std::make_shared<Response>(boost::beast::http::status::bad_request, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = "{\"error\":\"invalid timestamp format\"}"; res->prepare_payload(); self->send_response(res, cleaned_target); return; }
                                    if (ec2 || !r2.ok) { auto res = std::make_shared<Response>(boost::beast::http::status::internal_server_error, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = "{\"error\":\"internal\"}"; res->prepare_payload(); self->send_response(res, cleaned_target); return; }
                                    std::string items = "[";
                                    for (size_t i=0;i<r2.rows.size();++i){ if (i) items += ","; const auto& row = r2.rows[i]; auto s = [](const std::optional<std::string>& o){ return o.has_value() ? o.value() : std::string(); };
                                        if (row.size() >= 9) {
                                            items += std::string("{\"id\":\"") + json_escape_resp(s(row[0])) + "\",";
                                            items += std::string("\"event_id\":\"") + json_escape_resp(s(row[1])) + "\",";
                                            items += std::string("\"recurrence_rule_id\":") + (row[2].has_value() ? (std::string("\"") + json_escape_resp(s(row[2])) + std::string("\"")) : std::string("null")) + ",";
                                            items += std::string("\"title\":\"") + json_escape_resp(s(row[3])) + "\",";
                                            items += std::string("\"description\":") + (row[4].has_value() ? (std::string("\"") + json_escape_resp(row[4].value()) + std::string("\"")) : std::string("null")) + ",";
                                            items += std::string("\"start_ts\":\"") + json_escape_resp(normalize_iso_z(s(row[5]))) + "\",";
                                            items += std::string("\"end_ts\":") + (row[6].has_value() ? (std::string("\"") + json_escape_resp(normalize_iso_z(s(row[6]))) + std::string("\"")) : std::string("null")) + ",";
                                            items += std::string("\"created_by\":\"") + json_escape_resp(s(row[7])) + "\",";
                                            items += std::string("\"created_at\":\"") + json_escape_resp(s(row[8])) + "\"";
                                            items += std::string("}");
                                        } else {
                                            items += std::string("{\"id\":\"") + json_escape_resp(s(row[0])) + "\"," + "\"title\":\"" + json_escape_resp(s(row[1])) + "\",";
                                            items += std::string("\"description\":") + (row[2].has_value() ? (std::string("\"") + json_escape_resp(row[2].value()) + std::string("\"")) : std::string("null"));
                                            items += std::string(",\"start_ts\":\"") + json_escape_resp(normalize_iso_z(s(row[3]))) + "\"";
                                            items += std::string(",\"end_ts\":") + (row[4].has_value()
                                                ? (std::string("\"") + json_escape_resp(normalize_iso_z(s(row[4]))) + "\"")
                                                : std::string("null"));
                                            items += std::string(",\"created_by\":\"") + json_escape_resp(s(row[5])) + "\"";
                                            items += std::string(",\"created_at\":\"") + json_escape_resp(s(row[6])) + "\"";
                                            items += std::string("}");
                                        }
                                    }
                                    items += "]";
                                    std::string out = std::string("{\"items\":") + items + "}";
                                    auto res = std::make_shared<Response>(boost::beast::http::status::ok, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = out; res->prepare_payload(); self->send_response(res, cleaned_target);
                                });
                            }
                        });
                        return;
                    }
                }

                
                if (sub.rfind("events/", 0) == 0) {
                    
                    std::string event_path = sub.substr(std::string("events/").size());
                    size_t slash_pos = event_path.find('/');
                    std::string event_id = (slash_pos == std::string::npos) ? event_path : event_path.substr(0, slash_pos);
                    std::string event_tail = (slash_pos == std::string::npos) ? std::string() : event_path.substr(slash_pos + 1);

                    
                    if (event_tail.rfind("occurrences/", 0) == 0 && std::string(req.method_string()) == "GET") {
                        std::string start_ts = url_decode(event_tail.substr(std::string("occurrences/").size()));
                        
                        if (start_ts.empty()) {
                            auto res = std::make_shared<Response>(boost::beast::http::status::bad_request, req.version());
                            res->set(boost::beast::http::field::content_type, "application/json");
                            res->keep_alive(req.keep_alive());
                            res->body() = "{\"error\":\"bad request\",\"message\":\"missing start_ts\"}";
                            res->prepare_payload();
                            send_response(res, cleaned_target);
                            return;
                        }
                        
                        std::tm tm{};
                        if (!parse_iso_z_utc(start_ts, tm)) {
                            auto res = std::make_shared<Response>(boost::beast::http::status::bad_request, req.version());
                            res->set(boost::beast::http::field::content_type, "application/json");
                            res->keep_alive(req.keep_alive());
                            res->body() = "{\"error\":\"bad request\",\"message\":\"invalid start_ts\"}";
                            res->prepare_payload();
                            send_response(res, cleaned_target);
                            return;
                        }
                        auto claims_opt = Session::authenticate_bearer(req, self->jwt_secret);
                        if (!claims_opt) {
                            auto res = std::make_shared<Response>(boost::beast::http::status::unauthorized, req.version());
                            res->set(boost::beast::http::field::content_type, "application/json");
                            res->keep_alive(req.keep_alive());
                            res->body() = "{\"error\":\"unauthorized\"}";
                            res->prepare_payload();
                            send_response(res, cleaned_target);
                            return;
                        }
                        auto cl = *claims_opt; auto self = shared_from_this();
                        
                        self->db->async_get_membership(calid, cl.sub, [self, cleaned_target, calid, event_id, start_ts](const boost::system::error_code& ecm, const db::DbResult& rm) {
                            if (ecm || !rm.ok || rm.rows.empty()) {
                                auto res = std::make_shared<Response>(boost::beast::http::status::forbidden, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = "{\"error\":\"forbidden\"}"; res->prepare_payload(); self->send_response(res, cleaned_target); return;
                            }
                            
                            
                            std::string from = start_ts;
                            std::string to = start_ts;
                            std::string from2, to2;
                            if (add_seconds_iso_z(start_ts, -1, from2)) from = from2;
                            if (add_seconds_iso_z(start_ts, 1, to2)) to = to2;
                            
                            if (to == from) to = "2100-01-01T00:00:00Z";

                            self->db->async_list_occurrences(calid, from, to, [self, cleaned_target, event_id, start_ts, from, to](const boost::system::error_code& ec2, const db::DbResult& r2) {
                                if (ec2 || !r2.ok) { auto res = std::make_shared<Response>(boost::beast::http::status::internal_server_error, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = "{\"error\":\"internal\"}"; res->prepare_payload(); self->send_response(res, cleaned_target); return; }
                                auto s = [](const std::optional<std::string>& o){ return o.has_value() ? o.value() : std::string(); };
                                
                                for (size_t i = 0; i < r2.rows.size(); ++i) {
                                    const auto& row = r2.rows[i];
                                    
                                    if (row.size() < 6) continue;
                                    std::string ev_id = s(row[1]);
                                    std::string row_start = s(row[5]);
                                    if (ev_id == event_id && normalize_iso_z(row_start) == normalize_iso_z(start_ts)) {
                                        std::string occ_id = s(row[0]);
                                        std::string rule_id = row.size() > 2 && row[2].has_value() ? row[2].value() : std::string();
                                        std::string title = s(row[3]);
                                        std::string desc = row.size() > 4 && row[4].has_value() ? row[4].value() : std::string();
                                        std::string start_ts_row = s(row[5]);
                                        std::optional<std::string> end_ts = row.size() > 6 && row[6].has_value() ? std::optional<std::string>(row[6].value()) : std::nullopt;
                                        
                                        
                                        std::string out = std::string("{") + "\"id\":\"" + json_escape_resp(occ_id.empty() ? ev_id : occ_id) + "\"," + "\"event_id\":\"" + json_escape_resp(ev_id) + "\",";
                                        out += std::string("\"recurrence_rule_id\":") + (rule_id.empty() ? std::string("null") : (std::string("\"") + json_escape_resp(rule_id) + std::string("\""))) + ",";
                                        out += std::string("\"title\":\"") + json_escape_resp(title) + "\",";
                                        out += std::string("\"description\":") + (desc.empty() ? std::string("null") : (std::string("\"") + json_escape_resp(desc) + std::string("\""))) + ",";
                                        out += std::string("\"start_ts\":\"") + json_escape_resp(normalize_iso_z(start_ts_row)) + "\",";
                                        out += std::string("\"end_ts\":") + (end_ts.has_value() ? (std::string("\"") + json_escape_resp(normalize_iso_z(end_ts.value())) + std::string("\"")) : std::string("null")) + ",";
                                        
                                        out += std::string("\"is_cancelled\":false,");
                                        out += std::string("\"override_id\":null") + std::string("}");
                                        auto res = std::make_shared<Response>(boost::beast::http::status::ok, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = out; res->prepare_payload(); self->send_response(res, cleaned_target);
                                        return;
                                    }
                                }
                                
                                try {
                                    std::ostringstream dbg;
                                    dbg << '{';
                                    dbg << "\"error\":\"not found\",";
                                    dbg << "\"debug_from\":\"" << json_escape_resp(from) << "\",";
                                    dbg << "\"debug_to\":\"" << json_escape_resp(to) << "\",";
                                    dbg << "\"debug_target_start\":\"" << json_escape_resp(start_ts) << "\",";
                                    dbg << "\"debug_target_start_norm\":\"" << json_escape_resp(normalize_iso_z(start_ts)) << "\",";
                                    dbg << "\"debug_rows\":" << r2.rows.size() << ',';
                                    dbg << "\"debug_sample\": [";
                                    size_t limit = std::min<size_t>(5, r2.rows.size());
                                    for (size_t ri = 0; ri < limit; ++ri) {
                                        const auto &row = r2.rows[ri];
                                        if (ri) dbg << ',';
                                        dbg << '{';
                                        dbg << "\"row_size\":" << row.size() << ',';
                                        auto val_or_empty = [&](size_t idx)->std::string{ if (idx < row.size() && row[idx].has_value()) return row[idx].value(); return std::string(); };
                                        std::string r0 = val_or_empty(0);
                                        std::string r1 = val_or_empty(1);
                                        std::string r2s = val_or_empty(2);
                                        std::string r5 = val_or_empty(5);
                                        dbg << "\"row0\":\"" << json_escape_resp(r0) << "\",";
                                        dbg << "\"row1\":\"" << json_escape_resp(r1) << "\",";
                                        dbg << "\"row2\":\"" << json_escape_resp(r2s) << "\",";
                                        dbg << "\"row5\":\"" << json_escape_resp(r5) << "\",";
                                        std::string r5norm = r5.empty() ? std::string() : normalize_iso_z(r5);
                                        dbg << "\"row5_norm\":\"" << json_escape_resp(r5norm) << "\"";
                                        dbg << '}';
                                    }
                                    dbg << ']';
                                    dbg << '}';
                                    auto res = std::make_shared<Response>(boost::beast::http::status::not_found, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = dbg.str(); res->prepare_payload(); self->send_response(res, cleaned_target);
                                } catch(...) {
                                    auto res = std::make_shared<Response>(boost::beast::http::status::not_found, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = "{\"error\":\"not found\"}"; res->prepare_payload(); self->send_response(res, cleaned_target);
                                }
                            });
                        });
                        return;
                    }

                    
                    if (event_tail == "occurrences") {
                        
                        if (std::string(req.method_string()) == "PATCH") {
                            auto claims_opt = Session::authenticate_bearer(req, self->jwt_secret);
                            if (!claims_opt) { auto res = std::make_shared<Response>(boost::beast::http::status::unauthorized, req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(req.keep_alive()); res->body() = "{\"error\":\"unauthorized\"}"; res->prepare_payload(); send_response(res, cleaned_target); return; }
                            auto cl = *claims_opt; auto self = shared_from_this();
                            try {
                                auto ct = self->req[boost::beast::http::field::content_type]; if (ct.find("application/json") == std::string::npos) throw std::runtime_error("bad content type"); if (self->req.body().size() > 16*1024) throw std::runtime_error("body too large");
                                
                                std::string original = json_extract_string(self->req.body(), "original_start_ts"); if (original.empty()) { auto res = std::make_shared<Response>(boost::beast::http::status::bad_request, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = "{\"error\":\"invalid input\"}"; res->prepare_payload(); self->send_response(res, cleaned_target); return; }
                                auto new_start_pair = json_extract_string_opt_present(self->req.body(), "new_start_ts"); auto new_end_pair = json_extract_string_opt_present(self->req.body(), "new_end_ts"); auto title_pair = json_extract_string_opt_present(self->req.body(), "title"); auto notes_pair = json_extract_string_opt_present(self->req.body(), "notes");
                                bool cancelled = false; auto cancelled_pair = json_extract_int_opt(self->req.body(), "cancelled"); if (cancelled_pair.has_value()) cancelled = (*cancelled_pair != 0);
                                std::optional<std::string> new_start = new_start_pair.first ? std::optional<std::string>(new_start_pair.second) : std::nullopt;
                                std::optional<std::string> new_end = new_end_pair.first ? std::optional<std::string>(new_end_pair.second) : std::nullopt;
                                std::optional<std::string> title = title_pair.first ? std::optional<std::string>(title_pair.second) : std::nullopt;
                                std::optional<std::string> notes = notes_pair.first ? std::optional<std::string>(notes_pair.second) : std::nullopt;
                                
                                self->db->async_get_membership(calid, cl.sub, [self, cleaned_target, event_id, original, new_start, new_end, title, notes, cancelled, calid](const boost::system::error_code& ecm, const db::DbResult& rm) {
                                    if (ecm || !rm.ok || rm.rows.empty()) { auto res = std::make_shared<Response>(boost::beast::http::status::forbidden, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = "{\"error\":\"forbidden\"}"; res->prepare_payload(); self->send_response(res, cleaned_target); return; }
                                    int role = 0; if (rm.rows[0][2].has_value()) { auto parsed = json_parse_int32_strict(rm.rows[0][2]); if (!parsed.has_value()) { auto res = std::make_shared<Response>(boost::beast::http::status::forbidden, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = "{\"error\":\"forbidden\"}"; res->prepare_payload(); self->send_response(res, cleaned_target); return; } role = *parsed; }
                                    if (role < 1) { auto res = std::make_shared<Response>(boost::beast::http::status::forbidden, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = "{\"error\":\"forbidden\"}"; res->prepare_payload(); self->send_response(res, cleaned_target); return; }

                                    
                                    std::string sql = "SELECT id FROM recurrence_rules WHERE event_id=$1 LIMIT 1";
                                    self->db->async_exec_params(sql, std::vector<std::string>{event_id}, [=](const boost::system::error_code& ec2, const db::DbResult& r2) {
                                        if (ec2 || !r2.ok || r2.rows.empty() || !r2.rows[0][0].has_value()) { auto res = std::make_shared<Response>(boost::beast::http::status::bad_request, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = "{\"error\":\"not a recurring event\"}"; res->prepare_payload(); self->send_response(res, cleaned_target); return; }
                                        std::string rule_id = r2.rows[0][0].value();
                                        
                                        self->db->async_upsert_occurrence_override(rule_id, original, new_start, new_end, title, notes, cancelled, [=](const boost::system::error_code& ec3, const db::DbResult& r3) {
                                            if (ec3 == boost::asio::error::invalid_argument) { auto res = std::make_shared<Response>(boost::beast::http::status::bad_request, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = "{\"error\":\"invalid timestamp format\"}"; res->prepare_payload(); self->send_response(res, cleaned_target); return; }
                                            if (ec3) { auto res = std::make_shared<Response>(boost::beast::http::status::internal_server_error, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = "{\"error\":\"internal\"}"; res->prepare_payload(); self->send_response(res, cleaned_target); return; }

                                            
                                            auto p1 = month_range_utc_from_ts(original);
                                            if (p1.first.empty()) { auto res = std::make_shared<Response>(boost::beast::http::status::bad_request, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = "{\"error\":\"invalid original timestamp\"}"; res->prepare_payload(); self->send_response(res, cleaned_target); return; }
                                            auto ranges = std::make_shared<std::vector<std::pair<std::string,std::string>>>(); ranges->push_back(p1);
                                            if (new_start.has_value()) {
                                                auto p2 = month_range_utc_from_ts(new_start.value()); if (!p2.first.empty() && p2.first != p1.first) ranges->push_back(p2);
                                            }

                                            
                                            try { if (self->redis && self->cache_enabled) { for (const auto &r : *ranges) { std::string yyyymm = r.first.substr(0,4) + r.first.substr(5,2); std::string key = std::string("ev:") + calid + ":" + yyyymm; self->redis->async_del(key, [](boost::system::error_code, int64_t){}); } } } catch(...) {}

                                            auto enqueue_next = std::make_shared<std::function<void(size_t)>>();
                                            *enqueue_next = [=](size_t idx) {
                                                if (idx >= ranges->size()) { auto res = std::make_shared<Response>(boost::beast::http::status::ok, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = "{\"status\":\"ok\"}"; res->prepare_payload(); self->send_response(res, cleaned_target); return; }
                                                const auto&r = (*ranges)[idx];
                                                std::string payload = std::string("{\"rule_id\":\"") + json_escape_resp(rule_id) + std::string("\",\"calendar_id\":\"") + json_escape_resp(calid) + std::string("\",\"range_start\":\"") + json_escape_resp(r.first) + std::string("\",\"range_end\":\"") + json_escape_resp(r.second) + std::string("\"}");
                                                self->db->async_enqueue_outbox_job("recompute_rule", payload, "", [self, cleaned_target, enqueue_next, idx](const boost::system::error_code& ec4, const db::DbResult& r4) {
                                                    if (ec4 || !r4.ok) { auto res = std::make_shared<Response>(boost::beast::http::status::internal_server_error, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = "{\"error\":\"internal\"}"; res->prepare_payload(); self->send_response(res, cleaned_target); return; }
                                                    (*enqueue_next)(idx+1);
                                                });
                                            };
                                            (*enqueue_next)(0);
                                        });
                                    });
                                });
                            } catch(...) { auto res = std::make_shared<Response>(boost::beast::http::status::bad_request, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = "{\"error\":\"invalid input\"}"; res->prepare_payload(); self->send_response(res, cleaned_target); return; }
                            return;
                        }

                        
                        if (std::string(req.method_string()) == "DELETE") {
                            auto claims_opt = Session::authenticate_bearer(req, self->jwt_secret);
                            if (!claims_opt) { auto res = std::make_shared<Response>(boost::beast::http::status::unauthorized, req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(req.keep_alive()); res->body() = "{\"error\":\"unauthorized\"}"; res->prepare_payload(); send_response(res, cleaned_target); return; }
                            auto cl = *claims_opt; auto self = shared_from_this();
                            try {
                                auto ct = self->req[boost::beast::http::field::content_type]; if (ct.find("application/json") == std::string::npos) throw std::runtime_error("bad content type"); if (self->req.body().size() > 8*1024) throw std::runtime_error("body too large");
                                std::string start_ts = json_extract_string(self->req.body(), "start_ts"); if (start_ts.empty()) { auto res = std::make_shared<Response>(boost::beast::http::status::bad_request, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = "{\"error\":\"invalid input\"}"; res->prepare_payload(); self->send_response(res, cleaned_target); return; }
                                
                                self->db->async_get_membership(calid, cl.sub, [self, cleaned_target, event_id, start_ts, calid](const boost::system::error_code& ecm, const db::DbResult& rm) {
                                    if (ecm || !rm.ok || rm.rows.empty()) { auto res = std::make_shared<Response>(boost::beast::http::status::forbidden, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = "{\"error\":\"forbidden\"}"; res->prepare_payload(); self->send_response(res, cleaned_target); return; }
                                    int role = 0; if (rm.rows[0][2].has_value()) { auto parsed = json_parse_int32_strict(rm.rows[0][2]); if (!parsed.has_value()) { auto res = std::make_shared<Response>(boost::beast::http::status::forbidden, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = "{\"error\":\"forbidden\"}"; res->prepare_payload(); self->send_response(res, cleaned_target); return; } role = *parsed; }
                                    if (role < 1) { auto res = std::make_shared<Response>(boost::beast::http::status::forbidden, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = "{\"error\":\"forbidden\"}"; res->prepare_payload(); self->send_response(res, cleaned_target); return; }
                                    
                                    std::string sql = "SELECT id FROM recurrence_rules WHERE event_id=$1 LIMIT 1";
                                    self->db->async_exec_params(sql, std::vector<std::string>{event_id}, [=](const boost::system::error_code& ec2, const db::DbResult& r2) {
                                        if (ec2 || !r2.ok || r2.rows.empty() || !r2.rows[0][0].has_value()) { auto res = std::make_shared<Response>(boost::beast::http::status::bad_request, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = "{\"error\":\"not a recurring event\"}"; res->prepare_payload(); self->send_response(res, cleaned_target); return; }
                                        std::string rule_id = r2.rows[0][0].value();
                                        self->db->async_upsert_occurrence_override(rule_id, start_ts, std::nullopt, std::nullopt, std::nullopt, std::nullopt, true, [=](const boost::system::error_code& ec3, const db::DbResult& r3) {
                                            if (ec3 == boost::asio::error::invalid_argument) { auto res = std::make_shared<Response>(boost::beast::http::status::bad_request, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = "{\"error\":\"invalid timestamp format\"}"; res->prepare_payload(); self->send_response(res, cleaned_target); return; }
                                            if (ec3) { auto res = std::make_shared<Response>(boost::beast::http::status::internal_server_error, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = "{\"error\":\"internal\"}"; res->prepare_payload(); self->send_response(res, cleaned_target); return; }
                                            
                                            auto p1 = month_range_utc_from_ts(start_ts);
                                            if (p1.first.empty()) { auto res = std::make_shared<Response>(boost::beast::http::status::bad_request, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = "{\"error\":\"invalid timestamp\"}"; res->prepare_payload(); self->send_response(res, cleaned_target); return; }
                                            std::string payload = std::string("{\"rule_id\":\"") + json_escape_resp(rule_id) + std::string("\",\"calendar_id\":\"") + json_escape_resp(calid) + std::string("\",\"range_start\":\"") + json_escape_resp(p1.first) + std::string("\",\"range_end\":\"") + json_escape_resp(p1.second) + std::string("\"}");
                                            self->db->async_enqueue_outbox_job("recompute_rule", payload, "", [self, cleaned_target](const boost::system::error_code& ec4, const db::DbResult& r4) {
                                                if (ec4 || !r4.ok) { auto res = std::make_shared<Response>(boost::beast::http::status::internal_server_error, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = "{\"error\":\"internal\"}"; res->prepare_payload(); self->send_response(res, cleaned_target); return; }
                                                auto res = std::make_shared<Response>(boost::beast::http::status::ok, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = "{\"status\":\"ok\"}"; res->prepare_payload(); self->send_response(res, cleaned_target);
                                            });
                                        });
                                    });
                                });
                            } catch(...) { auto res = std::make_shared<Response>(boost::beast::http::status::bad_request, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = "{\"error\":\"invalid input\"}"; res->prepare_payload(); self->send_response(res, cleaned_target); return; }
                            return;
                        }
                    }

                    
                    if (std::string(req.method_string()) == "PATCH") {
                        auto claims_opt = Session::authenticate_bearer(req, self->jwt_secret);
                        if (!claims_opt) { auto res = std::make_shared<Response>(boost::beast::http::status::unauthorized, req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(req.keep_alive()); res->body() = "{\"error\":\"unauthorized\"}"; res->prepare_payload(); send_response(res, cleaned_target); return; }
                        auto cl = *claims_opt; auto self = shared_from_this();
                        self->db->async_get_membership(calid, cl.sub, [self, cleaned_target, calid, event_id, cl](const boost::system::error_code& ec, const db::DbResult& r) {
                            if (ec || !r.ok || r.rows.empty()) { auto res = std::make_shared<Response>(boost::beast::http::status::forbidden, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = "{\"error\":\"forbidden\"}"; res->prepare_payload(); self->send_response(res, cleaned_target); return; }
                            int role = 0;
                            if (r.rows[0][2].has_value()) {
                                auto parsed = json_parse_int32_strict(r.rows[0][2]);
                                if (!parsed) { auto res = std::make_shared<Response>(boost::beast::http::status::forbidden, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = "{\"error\":\"forbidden\"}"; res->prepare_payload(); self->send_response(res, cleaned_target); return; }
                                role = *parsed;
                            }
                            if (role < 1) { auto res = std::make_shared<Response>(boost::beast::http::status::forbidden, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = "{\"error\":\"forbidden\"}"; res->prepare_payload(); self->send_response(res, cleaned_target); return; }
                            
                            self->db->async_get_event(calid, event_id, [self, cleaned_target, calid, event_id](const boost::system::error_code& ec2, const db::DbResult& r2) {
                                if (ec2 || !r2.ok || r2.rows.empty()) { auto res = std::make_shared<Response>(boost::beast::http::status::not_found, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = "{\"error\":\"not found\"}"; res->prepare_payload(); self->send_response(res, cleaned_target); return; }
                                auto row = r2.rows[0];
                                std::string cur_title = row[2].has_value() ? row[2].value() : std::string();
                                std::optional<std::string> cur_desc = row[3].has_value() ? std::optional<std::string>(row[3].value()) : std::nullopt;
                                std::string cur_start = row[4].has_value() ? row[4].value() : std::string();
                                std::optional<std::string> cur_end = row[5].has_value() ? std::optional<std::string>(row[5].value()) : std::nullopt;
                                try {
                                    auto desc_pair = json_extract_string_opt_present(self->req.body(), "description");
                                    auto title_pair = json_extract_string_opt_present(self->req.body(), "title");
                                    auto start_pair = json_extract_string_opt_present(self->req.body(), "start_ts");
                                    auto end_pair = json_extract_string_opt_present(self->req.body(), "end_ts");
                                    std::string new_title = cur_title;
                                    if (title_pair.first) new_title = title_pair.second.has_value() ? title_pair.second.value() : std::string();
                                    std::optional<std::string> new_desc = cur_desc;
                                    if (desc_pair.first) { new_desc = desc_pair.second; }
                                    std::string new_start = cur_start;
                                    if (start_pair.first) new_start = start_pair.second.has_value() ? start_pair.second.value() : std::string();
                                    std::optional<std::string> new_end = cur_end;
                                    if (end_pair.first) { new_end = end_pair.second; }
                                    if (new_title.empty() || new_start.empty()) { auto res = std::make_shared<Response>(boost::beast::http::status::bad_request, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = "{\"error\":\"invalid input\"}"; res->prepare_payload(); self->send_response(res, cleaned_target); return; }
                                    self->db->async_update_event_full(calid, event_id, new_title, new_desc, new_start, new_end, [self, cleaned_target, calid, event_id, cur_start, new_start](const boost::system::error_code& ec3, const db::DbResult& r3) {
                                        if (ec3 == boost::asio::error::invalid_argument) { auto res = std::make_shared<Response>(boost::beast::http::status::bad_request, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = "{\"error\":\"invalid timestamp format\"}"; res->prepare_payload(); self->send_response(res, cleaned_target); return; }
                                        if (ec3 || !r3.ok || r3.rows.empty()) { auto res = std::make_shared<Response>(boost::beast::http::status::internal_server_error, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = "{\"error\":\"internal\"}"; res->prepare_payload(); self->send_response(res, cleaned_target); return; }
                                        const auto& row2 = r3.rows[0]; auto s = [](const std::optional<std::string>& o){ return o.has_value() ? o.value() : std::string(); };
                                        std::string out = std::string("{\"id\":\"") + json_escape_resp(s(row2[0])) + "\"," + "\"calendar_id\":\"" + json_escape_resp(s(row2[1])) + "\"," + "\"title\":\"" + json_escape_resp(s(row2[2])) + "\",";
                                        out += std::string("\"description\":") + (row2[3].has_value() ? (std::string("\"") + json_escape_resp(row2[3].value()) + std::string("\"")) : std::string("null"));
                                        out += std::string(",\"start_ts\":") + (row2[4].has_value() ? (std::string("\"") + json_escape_resp(s(row2[4])) + std::string("\"")) : std::string("null"));
                                        out += std::string(",\"end_ts\":") + (row2[5].has_value() ? (std::string("\"") + json_escape_resp(s(row2[5])) + std::string("\"")) : std::string("null"));
                                        out += std::string(",\"created_by\":\"") + json_escape_resp(s(row2[6])) + ",";
                                        out += std::string("\"created_at\":\"") + json_escape_resp(s(row2[7])) + ",";
                                        out += std::string("\"updated_at\":\"") + json_escape_resp(s(row2[8])) + "}";
                                        auto res = std::make_shared<Response>(boost::beast::http::status::ok, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = out; res->prepare_payload(); self->send_response(res, cleaned_target);
                                        try {
                                            if (self->redis && self->cache_enabled) {
                                                std::vector<std::string> months;
                                                auto v1 = months_touched(cur_start, std::nullopt);
                                                months.insert(months.end(), v1.begin(), v1.end());
                                                auto v2 = months_touched(new_start, std::nullopt);
                                                months.insert(months.end(), v2.begin(), v2.end());
                                                
                                                std::sort(months.begin(), months.end()); months.erase(std::unique(months.begin(), months.end()), months.end());
                                                if (!months.empty()) {
                                                    auto timer = std::make_shared<boost::asio::steady_timer>(self->socket.get_executor());
                                                    timer->expires_after(std::chrono::milliseconds(50));
                                                    auto pending = std::make_shared<std::atomic<int>>(months.size());
                                                    for (const auto &ym : months) {
                                                        std::string key = std::string("ev:") + calid + ":" + ym;
                                                        self->redis->async_del(key, [timer, pending, key](boost::system::error_code ec, int64_t) {
                                                            if (ec) observability::log_warn("cache_invalidate_error", {{"key", key}, {"err", int64_t(ec.value())}});
                                                            else observability::log_info("cache_invalidate_ok", {{"key", key}});
                                                            if (pending->fetch_sub(1) == 1) { boost::system::error_code ig; timer->cancel(ig); }
                                                        });
                                                    }
                                                    timer->async_wait([timer](const boost::system::error_code &ec) { if (!ec) observability::log_info("cache_invalidate_deadline_fired", {}); });
                                                }
                                            }
                                        } catch(...) {}
                                    });
                                } catch(...) { auto res = std::make_shared<Response>(boost::beast::http::status::bad_request, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = "{\"error\":\"invalid input\"}"; res->prepare_payload(); self->send_response(res, cleaned_target); return; }
                            });
                        });
                        return;
                    }
                    
                    if (std::string(req.method_string()) == "DELETE") {
                        auto claims_opt = Session::authenticate_bearer(req, self->jwt_secret);
                        if (!claims_opt) { auto res = std::make_shared<Response>(boost::beast::http::status::unauthorized, req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(req.keep_alive()); res->body() = "{\"error\":\"unauthorized\"}"; res->prepare_payload(); send_response(res, cleaned_target); return; }
                        auto cl = *claims_opt; auto self = shared_from_this();
                        self->db->async_get_membership(calid, cl.sub, [self, cleaned_target, calid, event_id](const boost::system::error_code& ec, const db::DbResult& r) {
                            if (ec || !r.ok || r.rows.empty()) { auto res = std::make_shared<Response>(boost::beast::http::status::forbidden, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = "{\"error\":\"forbidden\"}"; res->prepare_payload(); self->send_response(res, cleaned_target); return; }
                            int role = 0; if (r.rows[0][2].has_value()) {
                                auto parsed = json_parse_int32_strict(r.rows[0][2]);
                                if (!parsed.has_value()) { auto res = std::make_shared<Response>(boost::beast::http::status::forbidden, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = "{\"error\":\"forbidden\"}"; res->prepare_payload(); self->send_response(res, cleaned_target); return; }
                                role = *parsed;
                            }
                            if (role < 2) { auto res = std::make_shared<Response>(boost::beast::http::status::forbidden, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = "{\"error\":\"forbidden\"}"; res->prepare_payload(); self->send_response(res, cleaned_target); return; }
                            
                            self->db->async_get_event(calid, event_id, [self, cleaned_target, calid, event_id](const boost::system::error_code& ec0, const db::DbResult& r0) {
                                if (ec0 || !r0.ok || r0.rows.empty()) { auto res = std::make_shared<Response>(boost::beast::http::status::not_found, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = "{\"error\":\"not found\"}"; res->prepare_payload(); self->send_response(res, cleaned_target); return; }
                                std::string start_ts = r0.rows[0][3].has_value() ? r0.rows[0][3].value() : std::string();
                                std::optional<std::string> end_ts = r0.rows[0][4].has_value() ? std::optional<std::string>(r0.rows[0][4].value()) : std::nullopt;
                                self->db->async_delete_event(calid, event_id, [self, cleaned_target, calid, start_ts, end_ts](const boost::system::error_code& ec2, const db::DbResult& r2) {
                                    if (ec2 || !r2.ok) { auto res = std::make_shared<Response>(boost::beast::http::status::internal_server_error, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = "{\"error\":\"internal\"}"; res->prepare_payload(); self->send_response(res, cleaned_target); return; }
                                    
                                    try {
                                        if (self->redis && self->cache_enabled) {
                                            auto months = months_touched(start_ts, end_ts.has_value() ? std::optional<std::string_view>(std::string_view(end_ts.value())) : std::nullopt);
                                            if (!months.empty()) {
                                                auto timer = std::make_shared<boost::asio::steady_timer>(self->socket.get_executor());
                                                timer->expires_after(std::chrono::milliseconds(50));
                                                auto pending = std::make_shared<std::atomic<int>>(months.size());
                                                for (const auto &ym : months) {
                                                    std::string key = std::string("ev:") + calid + ":" + ym;
                                                    self->redis->async_del(key, [timer, pending, key](boost::system::error_code ec, int64_t) {
                                                        if (ec) observability::log_warn("cache_invalidate_error", {{"key", key}, {"err", int64_t(ec.value())}});
                                                        else observability::log_info("cache_invalidate_ok", {{"key", key}});
                                                        if (pending->fetch_sub(1) == 1) { boost::system::error_code ig; timer->cancel(ig); }
                                                    });
                                                }
                                                timer->async_wait([timer](const boost::system::error_code &ec) { if (!ec) observability::log_info("cache_invalidate_deadline_fired", {}); });
                                            }
                                        }
                                    } catch(...) {}
                                    auto res = std::make_shared<Response>(boost::beast::http::status::no_content, self->req.version()); res->keep_alive(self->req.keep_alive()); res->prepare_payload(); self->send_response(res, cleaned_target);
                                });
                            });
                        });
                        return;
                    }
                }

                
                if (sub == "tasks") {
                    if (std::string(req.method_string()) == "POST") {
                        auto claims_opt = Session::authenticate_bearer(req, self->jwt_secret);
                        if (!claims_opt) { auto res = std::make_shared<Response>(boost::beast::http::status::unauthorized, req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(req.keep_alive()); res->body() = "{\"error\":\"unauthorized\"}"; res->prepare_payload(); send_response(res, cleaned_target); return; }
                        auto cl = *claims_opt; auto self = shared_from_this();
                        self->db->async_get_membership(calid, cl.sub, [self, cleaned_target, calid, cl](const boost::system::error_code& ec, const db::DbResult& r) {
                            if (ec || !r.ok || r.rows.empty()) { auto res = std::make_shared<Response>(boost::beast::http::status::forbidden, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = "{\"error\":\"forbidden\"}"; res->prepare_payload(); self->send_response(res, cleaned_target); return; }
                            int role = 0; if (r.rows[0][2].has_value()) {
                                auto parsed = json_parse_int32_strict(r.rows[0][2]);
                                if (!parsed.has_value()) { auto res = std::make_shared<Response>(boost::beast::http::status::forbidden, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = "{\"error\":\"forbidden\"}"; res->prepare_payload(); self->send_response(res, cleaned_target); return; }
                                role = *parsed;
                            }
                            if (role < 1) { auto res = std::make_shared<Response>(boost::beast::http::status::forbidden, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = "{\"error\":\"forbidden\"}"; res->prepare_payload(); self->send_response(res, cleaned_target); return; }
                                try {
                                auto ct = self->req[boost::beast::http::field::content_type]; if (ct.find("application/json") == std::string::npos) throw std::runtime_error("bad content type"); if (self->req.body().size() > 16*1024) throw std::runtime_error("body too large");
                                std::string title = json_extract_string(self->req.body(), "title"); auto desc_pair = json_extract_string_opt_present(self->req.body(), "description"); auto due_pair = json_extract_string_opt_present(self->req.body(), "due_ts");
                                if (title.empty()) { auto res = std::make_shared<Response>(boost::beast::http::status::bad_request, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = "{\"error\":\"invalid input\"}"; res->prepare_payload(); self->send_response(res, cleaned_target); return; }
                                std::optional<std::string> desc_opt = desc_pair.first ? desc_pair.second : std::nullopt;
                                std::optional<std::string> due_opt = due_pair.first ? due_pair.second : std::nullopt;
                                self->db->async_create_task(calid, cl.sub, title, desc_opt, due_opt, [self, cleaned_target](const boost::system::error_code& ec2, const db::DbResult& r2) {
                                    if (ec2 == boost::asio::error::invalid_argument) { auto res = std::make_shared<Response>(boost::beast::http::status::bad_request, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = "{\"error\":\"invalid timestamp format\"}"; res->prepare_payload(); self->send_response(res, cleaned_target); return; }
                                    if (ec2 || !r2.ok || r2.rows.empty()) { auto res = std::make_shared<Response>(boost::beast::http::status::internal_server_error, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = "{\"error\":\"internal\"}"; res->prepare_payload(); self->send_response(res, cleaned_target); return; }
                                    const auto& row2 = r2.rows[0]; auto s = [](const std::optional<std::string>& o){ return o.has_value() ? o.value() : std::string(); };
                                    
                                    std::string out = std::string("{\"id\":\"") + json_escape_resp(s(row2[0])) + "\"," + "\"calendar_id\":\"" + json_escape_resp(s(row2[1])) + "\"," + "\"title\":\"" + json_escape_resp(s(row2[2])) + "\",";
                                    out += std::string("\"description\":") + (row2[3].has_value() ? (std::string("\"") + json_escape_resp(row2[3].value()) + std::string("\"")) : std::string("null"));
                                    out += std::string(",\"due_ts\":") + (row2[4].has_value() ? (std::string("\"") + json_escape_resp(s(row2[4])) + std::string("\"")) : std::string("null"));
                                    out += std::string(",\"status\":") + json_emit_int(row2[5], 0);
                                    out += std::string(",\"created_by\":\"") + json_escape_resp(s(row2[6])) + ",";
                                    out += std::string("\"created_at\":\"") + json_escape_resp(s(row2[7])) + ",";
                                    out += std::string("\"updated_at\":\"") + json_escape_resp(s(row2[8])) + "}";
                                    auto res = std::make_shared<Response>(boost::beast::http::status::created, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = out; res->prepare_payload(); self->send_response(res, cleaned_target);
                                });
                            } catch(...) { auto res = std::make_shared<Response>(boost::beast::http::status::bad_request, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = "{\"error\":\"invalid input\"}"; res->prepare_payload(); self->send_response(res, cleaned_target); return; }
                        });
                        return;
                    }
                    
                    if (std::string(req.method_string()) == "GET") {
                        auto claims_opt = Session::authenticate_bearer(req, self->jwt_secret);
                        if (!claims_opt) { auto res = std::make_shared<Response>(boost::beast::http::status::unauthorized, req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(req.keep_alive()); res->body() = "{\"error\":\"unauthorized\"}"; res->prepare_payload(); send_response(res, cleaned_target); return; }
                        auto cl = *claims_opt; auto self = shared_from_this();
                        self->db->async_get_membership(calid, cl.sub, [self, cleaned_target, calid](const boost::system::error_code& ec, const db::DbResult& r) {
                            if (ec || !r.ok || r.rows.empty()) { auto res = std::make_shared<Response>(boost::beast::http::status::forbidden, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = "{\"error\":\"forbidden\"}"; res->prepare_payload(); self->send_response(res, cleaned_target); return; }
                            
                            std::string qs = std::string(self->req.target()); auto qpos = qs.find('?'); std::optional<std::string> from, to; std::optional<int> status;
                            if (qpos != std::string::npos) {
                                std::string q = qs.substr(qpos+1);
                                auto find_q = [&](const std::string& key)->std::string{ std::string k = key + "="; size_t p = q.find(k); if (p == std::string::npos) return std::string(); size_t v = p + k.size(); size_t e = q.find('&', v); if (e==std::string::npos) e=q.size(); return q.substr(v, e-v); };
                                auto f = find_q("from"); if (!f.empty()) from = url_decode(f); auto t = find_q("to"); if (!t.empty()) to = url_decode(t); auto st = find_q("status"); if (!st.empty()) { auto parsed = parse_int_strict_sv(std::string_view(st)); if (parsed.has_value()) status = static_cast<int>(*parsed); }
                            }
                            self->db->async_list_tasks(calid, from, to, status, [self, cleaned_target](const boost::system::error_code& ec2, const db::DbResult& r2) {
                                if (ec2 == boost::asio::error::invalid_argument) { auto res = std::make_shared<Response>(boost::beast::http::status::bad_request, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = "{\"error\":\"invalid timestamp format\"}"; res->prepare_payload(); self->send_response(res, cleaned_target); return; }
                                if (ec2 || !r2.ok) { auto res = std::make_shared<Response>(boost::beast::http::status::internal_server_error, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = "{\"error\":\"internal\"}"; res->prepare_payload(); self->send_response(res, cleaned_target); return; }
                                std::string items = "[";
                                for (size_t i=0;i<r2.rows.size();++i) { if (i) items += ","; const auto& row = r2.rows[i]; auto s = [](const std::optional<std::string>& o){ return o.has_value() ? o.value() : std::string(); };
                                    items += std::string("{\"id\":\"") + json_escape_resp(s(row[0])) + "\"," + "\"title\":\"" + json_escape_resp(s(row[1])) + "\",";
                                    items += std::string("\"description\":") + (row[2].has_value() ? (std::string("\"") + json_escape_resp(row[2].value()) + std::string("\"")) : std::string("null"));
                                    items += std::string(",\"due_ts\":") + (row[3].has_value() ? (std::string("\"") + json_escape_resp(s(row[3])) + std::string("\"")) : std::string("null"));
                                    items += std::string(",\"status\":") + json_emit_int(row[4], 0) + std::string(",\"created_by\":\"") + json_escape_resp(s(row[5])) + ",";
                                    items += std::string("\"created_at\":\"") + json_escape_resp(s(row[6])) + ",";
                                    items += std::string("\"updated_at\":\"") + json_escape_resp(s(row[7])) + "}";
                                }
                                items += "]";
                                std::string out = std::string("{\"items\":") + items + "}";
                                auto res = std::make_shared<Response>(boost::beast::http::status::ok, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = out; res->prepare_payload(); self->send_response(res, cleaned_target);
                            });
                        });
                        return;
                    }
                }

                
                if (sub.rfind("tasks/", 0) == 0) {
                    std::string task_id = sub.substr(std::string("tasks/").size());
                    
                    if (std::string(req.method_string()) == "PATCH") {
                        auto claims_opt = Session::authenticate_bearer(req, self->jwt_secret);
                        if (!claims_opt) { auto res = std::make_shared<Response>(boost::beast::http::status::unauthorized, req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(req.keep_alive()); res->body() = "{\"error\":\"unauthorized\"}"; res->prepare_payload(); send_response(res, cleaned_target); return; }
                        auto cl = *claims_opt; auto self = shared_from_this();
                        self->db->async_get_membership(calid, cl.sub, [self, cleaned_target, calid, task_id](const boost::system::error_code& ec, const db::DbResult& r) {
                            if (ec || !r.ok || r.rows.empty()) { auto res = std::make_shared<Response>(boost::beast::http::status::forbidden, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = "{\"error\":\"forbidden\"}"; res->prepare_payload(); self->send_response(res, cleaned_target); return; }
                            int role = 0;
                            if (r.rows[0][2].has_value()) {
                                auto parsed = json_parse_int32_strict(r.rows[0][2]);
                                if (!parsed) { auto res = std::make_shared<Response>(boost::beast::http::status::forbidden, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = "{\"error\":\"forbidden\"}"; res->prepare_payload(); self->send_response(res, cleaned_target); return; }
                                role = *parsed;
                            }
                            if (role < 1) { auto res = std::make_shared<Response>(boost::beast::http::status::forbidden, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = "{\"error\":\"forbidden\"}"; res->prepare_payload(); self->send_response(res, cleaned_target); return; }
                            self->db->async_get_task(calid, task_id, [self, cleaned_target, calid, task_id](const boost::system::error_code& ec2, const db::DbResult& r2) {
                                if (ec2 || !r2.ok || r2.rows.empty()) { auto res = std::make_shared<Response>(boost::beast::http::status::not_found, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = "{\"error\":\"not found\"}"; res->prepare_payload(); self->send_response(res, cleaned_target); return; }
                                auto row = r2.rows[0]; std::string cur_title = row[2].has_value() ? row[2].value() : std::string(); std::optional<std::string> cur_desc = row[3].has_value() ? std::optional<std::string>(row[3].value()) : std::nullopt; std::optional<std::string> cur_due = row[4].has_value() ? std::optional<std::string>(row[4].value()) : std::nullopt; int cur_status = 0; if (row[5].has_value()) { auto parsed = json_parse_int32_strict(row[5]); if (!parsed.has_value()) { auto res = std::make_shared<Response>(boost::beast::http::status::forbidden, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = "{\"error\":\"forbidden\"}"; res->prepare_payload(); self->send_response(res, cleaned_target); return; } cur_status = *parsed; }
                                try {
                                    auto title_pair = json_extract_string_opt_present(self->req.body(), "title"); auto desc_pair = json_extract_string_opt_present(self->req.body(), "description"); auto due_pair = json_extract_string_opt_present(self->req.body(), "due_ts"); auto status_pair = json_extract_int_present(self->req.body(), "status");
                                    std::string new_title = cur_title;
                                    if (title_pair.first) new_title = title_pair.second.has_value() ? title_pair.second.value() : std::string();
                                    std::optional<std::string> new_desc = cur_desc;
                                    if (desc_pair.first) new_desc = desc_pair.second;
                                    std::optional<std::string> new_due = cur_due;
                                    if (due_pair.first) new_due = due_pair.second;
                                    int new_status = status_pair.first ? status_pair.second : cur_status; if (new_status !=0 && new_status !=1) { auto res = std::make_shared<Response>(boost::beast::http::status::bad_request, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = "{\"error\":\"invalid status\"}"; res->prepare_payload(); self->send_response(res, cleaned_target); return; }
                                    if (new_title.empty()) { auto res = std::make_shared<Response>(boost::beast::http::status::bad_request, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = "{\"error\":\"invalid input\"}"; res->prepare_payload(); self->send_response(res, cleaned_target); return; }
                                    self->db->async_update_task_full(calid, task_id, new_title, new_desc, new_due, new_status, [self, cleaned_target](const boost::system::error_code& ec3, const db::DbResult& r3) {
                                        if (ec3 == boost::asio::error::invalid_argument) { auto res = std::make_shared<Response>(boost::beast::http::status::bad_request, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = "{\"error\":\"invalid timestamp format\"}"; res->prepare_payload(); self->send_response(res, cleaned_target); return; }
                                        if (ec3 || !r3.ok || r3.rows.empty()) { auto res = std::make_shared<Response>(boost::beast::http::status::internal_server_error, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = "{\"error\":\"internal\"}"; res->prepare_payload(); self->send_response(res, cleaned_target); return; }
                                        const auto& row2 = r3.rows[0]; auto s = [](const std::optional<std::string>& o){ return o.has_value() ? o.value() : std::string(); };
                                        std::string out = std::string("{\"id\":\"") + json_escape_resp(s(row2[0])) + "\"," + "\"calendar_id\":\"" + json_escape_resp(s(row2[1])) + "\"," + "\"title\":\"" + json_escape_resp(s(row2[2])) + "\",";
                                        out += std::string("\"description\":") + (row2[3].has_value() ? (std::string("\"") + json_escape_resp(row2[3].value()) + std::string("\"")) : std::string("null"));
                                        out += std::string(",\"due_ts\":") + (row2[4].has_value() ? (std::string("\"") + json_escape_resp(s(row2[4])) + std::string("\"")) : std::string("null"));
                                        out += std::string(",\"status\":") + json_emit_int(row2[5], 0) + std::string(",\"created_by\":\"") + json_escape_resp(s(row2[6])) + ",";
                                        out += std::string("\"created_at\":\"") + json_escape_resp(s(row2[7])) + ",";
                                        out += std::string("\"updated_at\":\"") + json_escape_resp(s(row2[8])) + "}";
                                        auto res = std::make_shared<Response>(boost::beast::http::status::ok, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = out; res->prepare_payload(); self->send_response(res, cleaned_target);
                                    });
                                } catch(...) { auto res = std::make_shared<Response>(boost::beast::http::status::bad_request, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = "{\"error\":\"invalid input\"}"; res->prepare_payload(); self->send_response(res, cleaned_target); return; }
                            });
                        });
                        return;
                    }
                    
                    if (std::string(req.method_string()) == "DELETE") {
                        auto claims_opt = Session::authenticate_bearer(req, self->jwt_secret);
                        if (!claims_opt) { auto res = std::make_shared<Response>(boost::beast::http::status::unauthorized, req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(req.keep_alive()); res->body() = "{\"error\":\"unauthorized\"}"; res->prepare_payload(); send_response(res, cleaned_target); return; }
                        auto cl = *claims_opt; auto self = shared_from_this();
                        self->db->async_get_membership(calid, cl.sub, [self, cleaned_target, calid, task_id](const boost::system::error_code& ec, const db::DbResult& r) {
                            if (ec || !r.ok || r.rows.empty()) { auto res = std::make_shared<Response>(boost::beast::http::status::forbidden, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = "{\"error\":\"forbidden\"}"; res->prepare_payload(); self->send_response(res, cleaned_target); return; }
                            int role = 0;
                            if (r.rows[0][2].has_value()) {
                                auto parsed = json_parse_int32_strict(r.rows[0][2]);
                                if (!parsed) { auto res = std::make_shared<Response>(boost::beast::http::status::forbidden, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = "{\"error\":\"forbidden\"}"; res->prepare_payload(); self->send_response(res, cleaned_target); return; }
                                role = *parsed;
                            }
                            if (role < 2) { auto res = std::make_shared<Response>(boost::beast::http::status::forbidden, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = "{\"error\":\"forbidden\"}"; res->prepare_payload(); self->send_response(res, cleaned_target); return; }
                            self->db->async_delete_task(calid, task_id, [self, cleaned_target](const boost::system::error_code& ec2, const db::DbResult& r2) {
                                if (ec2 || !r2.ok) { auto res = std::make_shared<Response>(boost::beast::http::status::internal_server_error, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = "{\"error\":\"internal\"}"; res->prepare_payload(); self->send_response(res, cleaned_target); return; }
                                auto res = std::make_shared<Response>(boost::beast::http::status::no_content, self->req.version()); res->keep_alive(self->req.keep_alive()); res->prepare_payload(); self->send_response(res, cleaned_target);
                            });
                        });
                        return;
                    }
                }

                
                if (sub == "members" && std::string(req.method_string()) == "GET") {
                    auto claims_opt = Session::authenticate_bearer(req, self->jwt_secret);
                    if (!claims_opt) { auto res = std::make_shared<Response>(boost::beast::http::status::unauthorized, req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(req.keep_alive()); res->body() = "{\"error\":\"unauthorized\"}"; res->prepare_payload(); send_response(res, cleaned_target); return; }
                    auto cl = *claims_opt;
                    auto self = shared_from_this();
                    self->db->async_get_membership(calid, cl.sub, [self, cleaned_target, calid](const boost::system::error_code& ec, const db::DbResult& r) {
                        if (ec || !r.ok || r.rows.empty()) { auto res = std::make_shared<Response>(boost::beast::http::status::forbidden, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = "{\"error\":\"forbidden\"}"; res->prepare_payload(); self->send_response(res, cleaned_target); return; }
                        int role = 0;
                        if (r.rows[0][2].has_value()) {
                            auto parsed = json_parse_int32_strict(r.rows[0][2]);
                            if (!parsed.has_value()) { auto res = std::make_shared<Response>(boost::beast::http::status::forbidden, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = "{\"error\":\"forbidden\"}"; res->prepare_payload(); self->send_response(res, cleaned_target); return; }
                            role = *parsed;
                        }
                        if (role < 1) { auto res = std::make_shared<Response>(boost::beast::http::status::forbidden, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = "{\"error\":\"forbidden\"}"; res->prepare_payload(); self->send_response(res, cleaned_target); return; }
                        self->db->async_list_memberships(calid, [self, cleaned_target](const boost::system::error_code& ec2, const db::DbResult& r2) {
                            if (ec2 || !r2.ok) { auto res = std::make_shared<Response>(boost::beast::http::status::internal_server_error, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = "{\"error\":\"internal\"}"; res->prepare_payload(); self->send_response(res, cleaned_target); return; }
                            auto s = [](const std::optional<std::string>& o){ return o.has_value() ? o.value() : std::string(); };
                            std::string out = "[";
                                for (size_t i = 0; i < r2.rows.size(); ++i) {
                                if (i) out += ",";
                                const auto& row = r2.rows[i];
                                out += std::string("{\"user_id\":\"") + json_escape_resp(s(row[0])) + "\",\"email\":\"" + json_escape_resp(s(row[1])) + "\",\"role\":" + json_emit_int(row[2], 0) + "}";
                            }
                            out += "]";
                            auto res = std::make_shared<Response>(boost::beast::http::status::ok, self->req.version()); res->set(boost::beast::http::field::content_type, "application/json"); res->keep_alive(self->req.keep_alive()); res->body() = out; res->prepare_payload(); self->send_response(res, cleaned_target);
                        });
                    });
                    return;
                }
            }
        }

        if (cleaned_target == "/auth/login" && std::string(req.method_string()) == "POST") {
            try {
                auto ct = req[boost::beast::http::field::content_type];
                if (ct.find("application/json") == std::string::npos) throw std::runtime_error("bad content type");
                if (req.body().size() > 32 * 1024) throw std::runtime_error("body too large");

                std::string email = json_extract_string(req.body(), "email");
                std::string password = json_extract_string(req.body(), "password");
                auto trim = [](std::string s) {
                    size_t a = 0; while (a < s.size() && isspace((unsigned char)s[a])) ++a;
                    size_t b = s.size(); while (b > a && isspace((unsigned char)s[b-1])) --b;
                    return s.substr(a, b-a);
                };
                auto to_lower = [](std::string s){ for (auto &c: s) c = (char)std::tolower((unsigned char)c); return s; };
                email = to_lower(trim(email));
                if (email.empty() || password.empty() || password.size() < 8) {
                    auto res = std::make_shared<Response>(boost::beast::http::status::unauthorized, req.version());
                    res->set(boost::beast::http::field::content_type, "application/json");
                    res->keep_alive(req.keep_alive());
                    res->body() = "{\"error\":\"invalid credentials\"}";
                    res->prepare_payload();
                    send_response(res, cleaned_target);
                    return;
                }
                if (!db) {
                    auto res = std::make_shared<Response>(boost::beast::http::status::internal_server_error, req.version());
                    res->set(boost::beast::http::field::content_type, "application/json");
                    res->keep_alive(req.keep_alive());
                    res->body() = "{\"error\":\"db unavailable\"}";
                    res->prepare_payload();
                    send_response(res, cleaned_target);
                    return;
                }
                auto self = shared_from_this();
                db->async_get_user_by_email(email, [self, password, cleaned_target](const boost::system::error_code& ec, const db::DbResult& r) {
                    if (ec) {
                        auto res = std::make_shared<Response>(boost::beast::http::status::unauthorized, self->req.version());
                        res->set(boost::beast::http::field::content_type, "application/json");
                        res->keep_alive(self->req.keep_alive());
                        res->body() = "{\"error\":\"invalid credentials\"}";
                        res->prepare_payload();
                        self->send_response(res, cleaned_target);
                        return;
                    }
                    if (!r.ok || r.rows.empty()) {
                        auto res = std::make_shared<Response>(boost::beast::http::status::unauthorized, self->req.version());
                        res->set(boost::beast::http::field::content_type, "application/json");
                        res->keep_alive(self->req.keep_alive());
                        res->body() = "{\"error\":\"invalid credentials\"}";
                        res->prepare_payload();
                        self->send_response(res, cleaned_target);
                        return;
                    }
                    std::string id = r.rows[0][0].has_value() ? r.rows[0][0].value() : std::string();
                    std::string email = r.rows[0][1].has_value() ? r.rows[0][1].value() : std::string();
                    std::string pw_hash = r.rows[0][2].has_value() ? r.rows[0][2].value() : std::string();
                    
                    
                    if (!self->cpu_pool) {
                        boost::asio::post(self->socket.get_executor(), [self, cleaned_target]() {
                            auto res = std::make_shared<Response>(boost::beast::http::status::internal_server_error, self->req.version());
                            res->set(boost::beast::http::field::content_type, "application/json");
                            res->keep_alive(self->req.keep_alive());
                            res->body() = "{\"error\":\"internal\"}";
                            res->prepare_payload();
                            self->send_response(res, cleaned_target);
                        });
                    } else {
                        auto cpu_pool = self->cpu_pool;
                        boost::asio::post(*cpu_pool, [self, id, email, pw_hash, password, cleaned_target]() mutable {
                            bool ok = auth::verify_password(password, pw_hash);
                            boost::asio::post(self->socket.get_executor(), [self, ok, id, email, cleaned_target]() {
                                if (!ok) {
                                    auto res = std::make_shared<Response>(boost::beast::http::status::unauthorized, self->req.version());
                                    res->set(boost::beast::http::field::content_type, "application/json");
                                    res->keep_alive(self->req.keep_alive());
                                    res->body() = "{\"error\":\"invalid credentials\"}";
                                    res->prepare_payload();
                                    self->send_response(res, cleaned_target);
                                    return;
                                }
                                
                                if (self->jwt_secret.empty()) {
                                    auto res = std::make_shared<Response>(boost::beast::http::status::internal_server_error, self->req.version());
                                    res->set(boost::beast::http::field::content_type, "application/json");
                                    res->keep_alive(self->req.keep_alive());
                                    res->body() = "{\"error\":\"internal\"}";
                                    res->prepare_payload();
                                    self->send_response(res, cleaned_target);
                                    return;
                                }
                                auth::Claims cl;
                                cl.sub = id;
                                cl.email = email;
                                cl.iat = std::time(nullptr);
                                cl.exp = cl.iat + 24*3600;
                                std::string token = auth::create_jwt(cl, self->jwt_secret);
                                auto res = std::make_shared<Response>(boost::beast::http::status::ok, self->req.version());
                                res->set(boost::beast::http::field::content_type, "application/json");
                                res->keep_alive(self->req.keep_alive());
                                std::string out = std::string("{\"token\":\"") + json_escape_resp(token) + "\"}";
                                res->body() = out;
                                res->prepare_payload();
                                self->send_response(res, cleaned_target);
                            });
                        });
                    }
                });
            } catch (...) {
                auto res = std::make_shared<Response>(boost::beast::http::status::unauthorized, req.version());
                res->set(boost::beast::http::field::content_type, "application/json");
                res->keep_alive(req.keep_alive());
                res->body() = "{\"error\":\"invalid credentials\"}";
                res->prepare_payload();
                send_response(res, cleaned_target);
            }
            return;
        }

        if (cleaned_target == "/me" && std::string(req.method_string()) == "GET") {
            
            auto claims_opt = Session::authenticate_bearer(req, self->jwt_secret);
            if (!claims_opt) {
                auto res = std::make_shared<Response>(boost::beast::http::status::unauthorized, req.version());
                res->set(boost::beast::http::field::content_type, "application/json");
                res->keep_alive(req.keep_alive());
                res->body() = "{\"error\":\"unauthorized\"}";
                res->prepare_payload();
                send_response(res, cleaned_target);
                return;
            }
            auto cl = *claims_opt;
            
            if (!self->db) {
                auto res = std::make_shared<Response>(boost::beast::http::status::internal_server_error, req.version());
                res->set(boost::beast::http::field::content_type, "application/json");
                res->keep_alive(req.keep_alive());
                res->body() = "{\"error\":\"internal\"}";
                res->prepare_payload();
                send_response(res, cleaned_target);
                return;
            }
            self->db->async_get_user_by_id(cl.sub, [self, cleaned_target](const boost::system::error_code& ec, const db::DbResult& r) {
                if (ec || !r.ok || r.rows.empty()) {
                    auto res = std::make_shared<Response>(boost::beast::http::status::unauthorized, self->req.version());
                    res->set(boost::beast::http::field::content_type, "application/json");
                    res->keep_alive(self->req.keep_alive());
                    res->body() = "{\"error\":\"unauthorized\"}";
                    res->prepare_payload();
                    self->send_response(res, cleaned_target);
                    return;
                }
                std::string id = r.rows[0][0].has_value() ? r.rows[0][0].value() : std::string();
                std::string email = r.rows[0][1].has_value() ? r.rows[0][1].value() : std::string();
                auto res = std::make_shared<Response>(boost::beast::http::status::ok, self->req.version());
                res->set(boost::beast::http::field::content_type, "application/json");
                res->keep_alive(self->req.keep_alive());
                std::string out = std::string("{\"id\":\"") + json_escape_resp(id) + "\",\"email\":\"" + json_escape_resp(email) + "\"}";
                res->body() = out;
                res->prepare_payload();
                self->send_response(res, cleaned_target);
            });
            return;
        }

        auto res = std::make_shared<Response>(router.route(req));
        send_response(res, cleaned_target);
    }
    
    void send_response(std::shared_ptr<Response> res, const std::string& cleaned_target) {
        auto self = shared_from_this();
    
    auto sp = std::move(res);
    
    if (sp->find(boost::beast::http::field::connection) == sp->end()) {
        sp->keep_alive(self->req.keep_alive());
    }
    
    
    try {
        auto it = self->req.find(boost::beast::http::field::origin);
        if (it != self->req.end()) sp->set("Access-Control-Allow-Origin", std::string(it->value())); else sp->set("Access-Control-Allow-Origin", "*");
        sp->set("Access-Control-Allow-Credentials", "true");
    } catch(...) {}
        
        boost::beast::http::async_write(socket, *sp, [self, sp, cleaned_target](boost::system::error_code ec, std::size_t) {
            if (ec) {
                observability::log_warn("write_error", {{"path", cleaned_target}, {"err", int64_t(ec.value())}});
                
                self->close_socket();
                return;
            }
            
            
            if (sp->keep_alive()) {
                
                self->do_read();
            } else {
                
                try { self->graceful_close_after_write(); } catch (...) { self->close_socket(); }
            }
        });
    }

    
    
    
    void close_socket(bool hard_shutdown = true) {
        boost::system::error_code ignored;
        try { read_timer.cancel(ignored); } catch (...) {}
        try { socket.cancel(ignored); } catch (...) {}
        if (hard_shutdown) {
            try { socket.shutdown(net::ip::tcp::socket::shutdown_both, ignored); } catch (...) {}
        }
        try {
            socket.close(ignored);
        } catch (...) {}
    }

    
    
    void start_drain_timer() {
        auto self = shared_from_this();
        boost::system::error_code ignored;
        try { read_timer.cancel(ignored); } catch (...) {}
        try { read_timer.expires_after(std::chrono::seconds(drain_seconds_)); } catch (...) {}
        observability::log_info("drain_timer_started", {{"path", std::string("(drain)")}});
        read_timer.async_wait([self](const boost::system::error_code& ec) {
            observability::log_info("drain_timer_fired", {{"ec", int64_t(ec.value())}});
            if (ec) return; 
            
            self->close_socket(false);
        });
    }

    void do_drain_read() {
        auto self = shared_from_this();
        observability::log_info("drain_read_start", {{"path", std::string("(drain)")}});
        socket.async_read_some(net::buffer(drain_buf_), [self](boost::system::error_code ec, std::size_t n) {
            observability::log_info("drain_read_cb", {{"ec", int64_t(ec.value())}, {"n", int64_t(n)}});
            if (ec) {
                
                if (ec == boost::asio::error::operation_aborted) return;
                
                boost::system::error_code ignored;
                try { self->read_timer.cancel(ignored); } catch (...) {}
                self->close_socket(false);
                return;
            }
            
            try { self->do_drain_read(); } catch (...) { self->close_socket(false); }
        });
    }

    void graceful_close_after_write() {
        if (draining_) return;
        draining_ = true;
        boost::system::error_code ignored;
        try { socket.shutdown(net::ip::tcp::socket::shutdown_send, ignored); } catch (...) {}
        start_drain_timer();
        do_drain_read();
    }

    
    void reply_json_error(boost::beast::http::status st, const std::string& body, bool close_conn, const std::string& cleaned_target) {
        auto res = std::make_shared<Response>(st, http_version);
        res->set(boost::beast::http::field::content_type, "application/json");
        
        try {
            auto it = req.find(boost::beast::http::field::origin);
            if (it != req.end()) res->set("Access-Control-Allow-Origin", std::string(it->value())); else res->set("Access-Control-Allow-Origin", "*");
            res->set("Access-Control-Allow-Credentials", "true");
        } catch(...) {}
        res->keep_alive(!close_conn && req.keep_alive());
        res->body() = body;
        res->prepare_payload();
        if (close_conn) {
            res->set(boost::beast::http::field::connection, "close");
            
            boost::beast::http::async_write(socket, *res, [self=shared_from_this(), res, cleaned_target](boost::system::error_code ec, std::size_t) {
                observability::log_info("async_write_done", {{"path", cleaned_target}, {"err", int64_t(ec.value())}});
                if (ec) {
                    observability::log_warn("write_error", {{"path", cleaned_target}, {"err", int64_t(ec.value())}});
                    self->close_socket();
                    return;
                }
                
                observability::log_info("starting_graceful_close", {{"path", cleaned_target}});
                try { self->graceful_close_after_write(); } catch (...) { self->close_socket(); }
            });
        } else {
            
            send_response(res, cleaned_target);
        }
    }

    
    static std::optional<auth::Claims> authenticate_bearer(const Request& req, const std::string& jwt_secret) {
        auto it = req.find(boost::beast::http::field::authorization);
        if (it == req.end()) return std::nullopt;
    std::string v = std::string(it->value());
        const std::string prefix = "Bearer ";
        if (v.size() <= prefix.size()) return std::nullopt;
        if (v.compare(0, prefix.size(), prefix) != 0) return std::nullopt;
        std::string token = v.substr(prefix.size());
        return auth::verify_jwt(token, jwt_secret);
    }
};

HttpServer::HttpServer(net::io_context& ioc, unsigned short port, Router& router, bool metrics_enabled, bool access_log, std::shared_ptr<RedisClient> redis, bool cache_enabled, int cache_ttl_sec, bool cache_require_full_month_range, bool rate_limit_enabled, int rate_limit_limit, int rate_limit_window_ms, std::shared_ptr<db::DbPool> db, std::shared_ptr<boost::asio::thread_pool> cpu_pool, const std::string& jwt_secret)
    : ioc_(ioc), acceptor_(ioc, net::ip::tcp::endpoint(net::ip::address_v4::any(), port)), router_(router), metrics_enabled_(metrics_enabled), access_log_(access_log), redis_(redis), cache_enabled_(cache_enabled), cache_ttl_sec_(cache_ttl_sec), cache_require_full_month_range_(cache_require_full_month_range), db_(db), cpu_pool_(cpu_pool), jwt_secret_(jwt_secret), rate_limit_enabled_(rate_limit_enabled), rate_limit_limit_(rate_limit_limit), rate_limit_window_ms_(rate_limit_window_ms) {}

void HttpServer::run() { do_accept(); }

void HttpServer::do_accept() {
    acceptor_.async_accept([this](beast::error_code ec, net::ip::tcp::socket socket) {
        if (!ec) {
            auto s = std::make_shared<Session>(std::move(socket), router_, metrics_enabled_, access_log_, redis_, db_);
            s->rate_limit_enabled = rate_limit_enabled_;
            s->rate_limit_limit = rate_limit_limit_;
            s->rate_limit_window_ms = rate_limit_window_ms_;
            s->cpu_pool = cpu_pool_;
            s->jwt_secret = jwt_secret_;
            s->cache_enabled = cache_enabled_;
            s->cache_ttl_sec = cache_ttl_sec_;
            s->cache_require_full_month_range = cache_require_full_month_range_;
            s->run();
        } else observability::log_warn("accept error", {{"err", int64_t(ec.value())}});

        do_accept();
    });
}