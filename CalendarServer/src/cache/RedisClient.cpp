#include "RedisClient.h"
#include <boost/asio/connect.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <iostream>

RedisClient::RedisClient(IoContext& ioc, std::string host, uint16_t port, std::string pass)
    : ioc_(ioc), host_(std::move(host)), port_(port), socket_(ioc), redis_pass_(std::move(pass)) {}

void RedisClient::start() {
    do_connect();
}
static std::string resp_encode(const std::vector<std::string>& args) {
    std::string out;
    out += "*" + std::to_string(args.size()) + "\r\n";
    for (const auto& a : args) {
        out += "$" + std::to_string(a.size()) + "\r\n";
        out += a + "\r\n";
    }
    return out;
}
void RedisClient::do_connect() {
    
    auto resolver = std::make_shared<boost::asio::ip::tcp::resolver>(ioc_);
    resolver->async_resolve(host_, std::to_string(port_), [self = shared_from_this(), resolver](const boost::system::error_code& ec, boost::asio::ip::tcp::resolver::results_type eps) {
        if (ec) { self->connected_ = false; std::cerr << "redis resolve error: " << ec.message() << std::endl; return; }
        
        boost::system::error_code ig; self->socket_.close(ig);
        boost::asio::async_connect(self->socket_, eps, [self](const boost::system::error_code& ec2, const boost::asio::ip::tcp::endpoint&) {
            if (ec2) { self->connected_ = false; std::cerr << "redis connect error: " << ec2.message() << std::endl; return; }
            
            if (self->redis_pass_.empty()) {
                self->connected_ = true;
                self->do_write_next();
                return;
            }
            
            auto auth_cmd = resp_encode({"AUTH", self->redis_pass_});
            boost::asio::async_write(self->socket_, boost::asio::buffer(auth_cmd), [self](const boost::system::error_code& ecw, std::size_t) {
                if (ecw) { std::cerr << "redis auth write error: " << ecw.message() << std::endl; self->connected_ = false; self->socket_.close(); self->do_connect(); return; }
                
                boost::asio::async_read_until(self->socket_, self->read_buf_, "\r\n", [self](const boost::system::error_code& ecr, std::size_t) {
                    if (ecr) { std::cerr << "redis auth read error: " << ecr.message() << std::endl; self->connected_ = false; self->socket_.close(); self->do_connect(); return; }
                    std::istream is(&self->read_buf_);
                    std::string line; std::getline(is, line); if (!line.empty() && line.back() == '\r') line.pop_back();
                    if (!line.empty() && line[0] == '+') {
                        
                        self->connected_ = true;
                        self->do_write_next();
                        return;
                    }
                    
                    std::cerr << "redis auth failed: reply='" << line << "'" << std::endl;
                    self->connected_ = false; self->socket_.close(); self->do_connect();
                });
            });
        });
    });
}

void RedisClient::async_incr(const std::string& key, std::function<void(boost::system::error_code, int64_t)> cb) {
    Pending p;
    p.type = Pending::Type::Integer;
    p.int_cb = std::move(cb);
    auto cmd = resp_encode({"INCR", key});
    p.cmd = std::move(cmd);
    if (!connected_) {
        do_connect();
        boost::asio::post(ioc_, [cb=std::move(p.int_cb)]() mutable { if (cb) cb(boost::asio::error::not_connected, 0); });
        return;
    }
    if (queue_.size() >= MAX_QUEUE) {
        boost::asio::post(ioc_, [cb=std::move(p.int_cb)]() mutable { if (cb) cb(boost::asio::error::no_buffer_space, 0); });
        return;
    }
    queue_.push_back(std::move(p));
    do_write_next();
}

void RedisClient::async_pexpire(const std::string& key, int ttl_ms, std::function<void(boost::system::error_code, bool)> cb) {
    Pending p;
    p.type = Pending::Type::Bool;
    p.bool_cb = std::move(cb);
    auto cmd = resp_encode({"PEXPIRE", key, std::to_string(ttl_ms)});
    p.cmd = std::move(cmd);
    if (!connected_) {
        do_connect();
        boost::asio::post(ioc_, [cb=std::move(p.bool_cb)]() mutable { if (cb) cb(boost::asio::error::not_connected, false); });
        return;
    }
    if (queue_.size() >= MAX_QUEUE) {
        boost::asio::post(ioc_, [cb=std::move(p.bool_cb)]() mutable { if (cb) cb(boost::asio::error::no_buffer_space, false); });
        return;
    }
    queue_.push_back(std::move(p));
    do_write_next();
}

void RedisClient::async_get(const std::string& key, std::function<void(boost::system::error_code, std::optional<std::string>)> cb) {
    Pending p;
    p.type = Pending::Type::BulkString;
    p.bulk_cb = std::move(cb);
    auto cmd = resp_encode({"GET", key});
    p.cmd = std::move(cmd);
    if (!connected_) {
        do_connect();
        boost::asio::post(ioc_, [cb=std::move(p.bulk_cb)]() mutable { if (cb) cb(boost::asio::error::not_connected, std::nullopt); });
        return;
    }
    if (queue_.size() >= MAX_QUEUE) {
        boost::asio::post(ioc_, [cb=std::move(p.bulk_cb)]() mutable { if (cb) cb(boost::asio::error::no_buffer_space, std::nullopt); });
        return;
    }
    queue_.push_back(std::move(p));
    do_write_next();
}

void RedisClient::async_setex(const std::string& key, int ttl_sec, const std::string& value, std::function<void(boost::system::error_code, bool)> cb) {
    Pending p;
    p.type = Pending::Type::Bool;
    p.bool_cb = std::move(cb);
    auto cmd = resp_encode({"SETEX", key, std::to_string(ttl_sec), value});
    p.cmd = std::move(cmd);
    if (!connected_) {
        do_connect();
        boost::asio::post(ioc_, [cb=std::move(p.bool_cb)]() mutable { if (cb) cb(boost::asio::error::not_connected, false); });
        return;
    }
    if (queue_.size() >= MAX_QUEUE) {
        boost::asio::post(ioc_, [cb=std::move(p.bool_cb)]() mutable { if (cb) cb(boost::asio::error::no_buffer_space, false); });
        return;
    }
    queue_.push_back(std::move(p));
    do_write_next();
}

void RedisClient::async_del(const std::string& key, std::function<void(boost::system::error_code, int64_t)> cb) {
    Pending p;
    p.type = Pending::Type::Integer;
    p.int_cb = std::move(cb);
    auto cmd = resp_encode({"DEL", key});
    p.cmd = std::move(cmd);
    if (!connected_) {
        do_connect();
        boost::asio::post(ioc_, [cb=std::move(p.int_cb)]() mutable { if (cb) cb(boost::asio::error::not_connected, 0); });
        return;
    }
    if (queue_.size() >= MAX_QUEUE) {
        boost::asio::post(ioc_, [cb=std::move(p.int_cb)]() mutable { if (cb) cb(boost::asio::error::no_buffer_space, 0); });
        return;
    }
    queue_.push_back(std::move(p));
    do_write_next();
}

void RedisClient::do_write_next() {
    if (busy_ || !connected_ || queue_.empty()) return;
    busy_ = true; 
    
    current_ = std::move(queue_.front());
    queue_.pop_front();
    auto& p = *current_;
    boost::asio::async_write(socket_, boost::asio::buffer(p.cmd), [self=shared_from_this()](const boost::system::error_code& ec, std::size_t bytes) {
        self->on_write(ec, bytes);
    });
}

void RedisClient::on_write(const boost::system::error_code& ec, std::size_t) {
    if (ec) {
        
        if (current_.has_value()) {
            auto p = std::move(*current_);
            current_.reset();
            if (p.type == Pending::Type::Integer && p.int_cb) p.int_cb(ec, 0);
            if (p.type == Pending::Type::Bool && p.bool_cb) p.bool_cb(ec, false);
            if (p.type == Pending::Type::BulkString && p.bulk_cb) p.bulk_cb(ec, std::nullopt);
        }
        
        while (!queue_.empty()) {
            auto qp = std::move(queue_.front()); queue_.pop_front();
            if (qp.type == Pending::Type::Integer && qp.int_cb) qp.int_cb(boost::asio::error::not_connected, 0);
            if (qp.type == Pending::Type::Bool && qp.bool_cb) qp.bool_cb(boost::asio::error::not_connected, false);
            if (qp.type == Pending::Type::BulkString && qp.bulk_cb) qp.bulk_cb(boost::asio::error::not_connected, std::nullopt);
        }
        busy_ = false;
        connected_ = false;
        socket_.close();
        do_connect();
        return;
    }
    do_read();
}

void RedisClient::do_read() {
    
    boost::asio::async_read_until(socket_, read_buf_, "\r\n", [self=shared_from_this()](const boost::system::error_code& ec, std::size_t bytes) {
        self->on_read_line(ec, bytes);
    });
}

static boost::system::error_code make_protocol_error() {
    return boost::asio::error::fault;
}

void RedisClient::on_read_line(const boost::system::error_code& ec, std::size_t) {
    if (ec) {
        
        if (current_.has_value()) {
            auto p = std::move(*current_); current_.reset();
            if (p.type == Pending::Type::Integer && p.int_cb) p.int_cb(ec, 0);
            if (p.type == Pending::Type::Bool && p.bool_cb) p.bool_cb(ec, false);
            if (p.type == Pending::Type::BulkString && p.bulk_cb) p.bulk_cb(ec, std::nullopt);
        }
        while (!queue_.empty()) {
            auto qp = std::move(queue_.front()); queue_.pop_front();
            if (qp.type == Pending::Type::Integer && qp.int_cb) qp.int_cb(boost::asio::error::not_connected, 0);
            if (qp.type == Pending::Type::Bool && qp.bool_cb) qp.bool_cb(boost::asio::error::not_connected, false);
            if (qp.type == Pending::Type::BulkString && qp.bulk_cb) qp.bulk_cb(boost::asio::error::not_connected, std::nullopt);
        }
        busy_ = false;
        connected_ = false;
        socket_.close();
        do_connect();
        return;
    }

    std::istream is(&read_buf_);
    std::string line;
    std::getline(is, line);
    if (!line.empty() && line.back() == '\r') line.pop_back();

    if (!current_.has_value()) {
        
        if (!queue_.empty()) {
            current_ = std::move(queue_.front()); queue_.pop_front();
        } else {
            
            busy_ = false;
            do_write_next();
            return;
        }
    }

    auto p = std::move(*current_);

    
    if (!line.empty() && line[0] == ':') {
        int64_t val = 0;
        try { val = std::stoll(line.substr(1)); } catch(...) { val = 0; }
        if (p.type == Pending::Type::Integer && p.int_cb) p.int_cb({}, val);
        if (p.type == Pending::Type::Bool && p.bool_cb) p.bool_cb({}, val > 0);
        if (p.type == Pending::Type::BulkString && p.bulk_cb) p.bulk_cb({}, std::nullopt);
        current_.reset(); busy_ = false; do_write_next(); return;
    }

    if (!line.empty() && line[0] == '+') {
        if (p.type == Pending::Type::Bool && p.bool_cb) p.bool_cb({}, true);
        if (p.type == Pending::Type::Integer && p.int_cb) p.int_cb({}, 0);
        if (p.type == Pending::Type::BulkString && p.bulk_cb) p.bulk_cb({}, std::nullopt);
        current_.reset(); busy_ = false; do_write_next(); return;
    }

    if (!line.empty() && line[0] == '-') {
        auto err = make_protocol_error();
        if (p.type == Pending::Type::Bool && p.bool_cb) p.bool_cb(err, false);
        if (p.type == Pending::Type::Integer && p.int_cb) p.int_cb(err, 0);
        if (p.type == Pending::Type::BulkString && p.bulk_cb) p.bulk_cb(err, std::nullopt);
        current_.reset(); busy_ = false; do_write_next(); return;
    }

    if (!line.empty() && line[0] == '$') {
        int64_t len = 0;
        try { len = std::stoll(line.substr(1)); } catch(...) { len = -2; }
        if (len == -1) {
            if (p.type == Pending::Type::BulkString && p.bulk_cb) p.bulk_cb({}, std::nullopt);
            current_.reset(); busy_ = false; do_write_next(); return;
        }
        if (len < 0 || static_cast<std::size_t>(len) > MAX_BULK) {
            if (p.type == Pending::Type::BulkString && p.bulk_cb) p.bulk_cb(boost::asio::error::message_size, std::nullopt);
            
            connected_ = false; socket_.close(); do_connect();
            current_.reset(); busy_ = false; do_write_next(); return;
        }

        
        std::size_t need = static_cast<std::size_t>(len) + 2;
        if (read_buf_.size() >= need) {
            
            current_ = std::move(p); 
            std::size_t body_len = (need >= 2) ? (need - 2) : 0;
            consume_bulk_from_buffer_and_complete(body_len);
            return;
        }

        
        p.bulk_len = len;
        current_ = std::move(p); 
        std::size_t to_read = need - read_buf_.size();
        boost::asio::async_read(socket_, read_buf_, boost::asio::transfer_exactly(to_read), [self=shared_from_this(), need](const boost::system::error_code& ec2, std::size_t) {
            if (ec2) {
                self->on_read_line(ec2, 0);
                return;
            }
                
                if (need >= 2) {
                    
                    std::size_t body_len = (need >= 2) ? (need - 2) : 0;
                    self->consume_bulk_from_buffer_and_complete(body_len);
                } else {
                    self->consume_bulk_from_buffer_and_complete(0);
                }
        });
        return;
    }

    
    if (p.type == Pending::Type::Bool && p.bool_cb) p.bool_cb({}, false);
    if (p.type == Pending::Type::Integer && p.int_cb) p.int_cb({}, 0);
    if (p.type == Pending::Type::BulkString && p.bulk_cb) p.bulk_cb({}, std::nullopt);
    current_.reset(); busy_ = false; do_write_next();
}

void RedisClient::consume_bulk_from_buffer_and_complete(std::size_t len) {
    
    std::istream is(&read_buf_);
    std::string data; data.resize(len);
    if (len) {
        is.read(&data[0], static_cast<std::streamsize>(len));
        if (!is) {
            
            if (current_.has_value() && current_->bulk_cb) current_->bulk_cb(make_protocol_error(), std::nullopt);
            current_.reset(); busy_ = false; connected_ = false; boost::system::error_code ig; socket_.close(ig); do_connect();
            
            while (!queue_.empty()) { auto qp = std::move(queue_.front()); queue_.pop_front(); if (qp.type==Pending::Type::Integer && qp.int_cb) qp.int_cb(boost::asio::error::not_connected,0); if (qp.type==Pending::Type::Bool && qp.bool_cb) qp.bool_cb(boost::asio::error::not_connected,false); if (qp.type==Pending::Type::BulkString && qp.bulk_cb) qp.bulk_cb(boost::asio::error::not_connected,std::nullopt); }
            return;
        }
    }
    
    char cr = 0, lf = 0;
    is.get(cr);
    is.get(lf);
    if (cr != '\r' || lf != '\n') {
        if (current_.has_value() && current_->bulk_cb) current_->bulk_cb(make_protocol_error(), std::nullopt);
        current_.reset(); busy_ = false; connected_ = false; boost::system::error_code ig; socket_.close(ig); do_connect();
        while (!queue_.empty()) { auto qp = std::move(queue_.front()); queue_.pop_front(); if (qp.type==Pending::Type::Integer && qp.int_cb) qp.int_cb(boost::asio::error::not_connected,0); if (qp.type==Pending::Type::Bool && qp.bool_cb) qp.bool_cb(boost::asio::error::not_connected,false); if (qp.type==Pending::Type::BulkString && qp.bulk_cb) qp.bulk_cb(boost::asio::error::not_connected,std::nullopt); }
        return;
    }
    
    if (current_.has_value() && current_->bulk_cb) current_->bulk_cb({}, std::optional<std::string>(std::move(data)));
    current_.reset(); busy_ = false; do_write_next();
}
