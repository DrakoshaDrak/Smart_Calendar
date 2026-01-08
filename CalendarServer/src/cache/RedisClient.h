#pragma once

#include <boost/asio.hpp>
#include <functional>
#include <string>
#include <deque>
#include <memory>
#include <optional>

class RedisClient : public std::enable_shared_from_this<RedisClient> {
public:
    using IoContext = boost::asio::io_context;
    RedisClient(IoContext& ioc, std::string host, uint16_t port, std::string pass = std::string());
    void start();
    void async_incr(const std::string& key, std::function<void(boost::system::error_code, int64_t)> cb);
    void async_pexpire(const std::string& key, int ttl_ms, std::function<void(boost::system::error_code, bool)> cb);
    void async_get(const std::string& key,
                   std::function<void(boost::system::error_code, std::optional<std::string>)> cb);

    void async_setex(const std::string& key, int ttl_sec, const std::string& value,
                     std::function<void(boost::system::error_code, bool)> cb);

    void async_del(const std::string& key,
                   std::function<void(boost::system::error_code, int64_t)> cb);
private:
    void do_connect();
    void do_write_next();
    void on_write(const boost::system::error_code& ec, std::size_t);
    void do_read();
    void on_read_line(const boost::system::error_code& ec, std::size_t bytes);

    struct Pending {
        std::string cmd;
        enum class Type { Integer, Bool, BulkString } type;
        std::function<void(boost::system::error_code, int64_t)> int_cb;
        std::function<void(boost::system::error_code, bool)> bool_cb;
        std::function<void(boost::system::error_code, std::optional<std::string>)> bulk_cb;
        int64_t bulk_len = 0;
    };

    IoContext& ioc_;
    std::string host_;
    uint16_t port_;
    std::string redis_pass_;
    boost::asio::ip::tcp::socket socket_;
    boost::asio::streambuf read_buf_;
    std::deque<Pending> queue_;
    
    std::optional<Pending> current_;
    bool busy_ = false; 
    bool connected_ = false;
    
    static constexpr std::size_t MAX_BULK = 4 * 1024 * 1024;
    
    static constexpr std::size_t MAX_QUEUE = 10000;
    
    void consume_bulk_from_buffer_and_complete(std::size_t len);
};
