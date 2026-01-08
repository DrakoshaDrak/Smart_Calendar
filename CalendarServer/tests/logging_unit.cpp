#include <iostream>
#include <sstream>
#include <string>
#include <thread>
#include <vector>
#include <regex>
#include <atomic>
#include <fstream>
#include "../src/observability/Logging.h"

using namespace observability;

static bool is_json_line(const std::string& s) {
    if (s.empty()) return false;
    
    return s.front() == '{' && s.find("\"level\"") != std::string::npos && s.find("\"msg\"") != std::string::npos;
}

int main() {
    
    set_log_level(2);
    const char *tmp1 = "/tmp/logging_unit_stage1.txt";
    std::fflush(stdout);
    int saved = dup(fileno(stdout));
    if (saved == -1) { std::cerr << "dup failed\n"; return 1; }
    FILE *f1 = freopen(tmp1, "w+", stdout);
    if (!f1) { std::cerr << "freopen stage1 failed\n"; return 1; }

    log_info("info-message");
    log_warn("warn-message");
    log_error("error-message");

    std::fflush(stdout);
    std::cout.flush();
    if (dup2(saved, fileno(stdout)) == -1) { std::cerr << "dup2 restore failed\n"; return 1; }
    close(saved);

    std::ifstream ifs1(tmp1);
    if (!ifs1) { std::cerr << "open tmp1 failed\n"; return 1; }
    std::string out((std::istreambuf_iterator<char>(ifs1)), std::istreambuf_iterator<char>());
    size_t lines = 0;
    for (char c : out) if (c == '\n') ++lines;
    if (lines < 3) { std::cerr << "expected >=3 log lines got " << lines << "\n"; return 1; }

    
    std::istringstream in(out);
    std::string line;
    bool saw_info = false, saw_warn = false, saw_error = false;
    while (std::getline(in, line)) {
        if (line.empty()) continue;
        if (!is_json_line(line)) { std::cerr << "line not json: " << line << "\n"; return 1; }
        if (line.find("\"level\":\"INFO\"") != std::string::npos) saw_info = true;
        if (line.find("\"level\":\"WARN\"") != std::string::npos) saw_warn = true;
        if (line.find("\"level\":\"ERROR\"") != std::string::npos) saw_error = true;
    }
    if (!saw_info || !saw_warn || !saw_error) { std::cerr << "missing level outputs info=" << saw_info << " warn=" << saw_warn << " err=" << saw_error << "\n"; return 1; }

    if (out.find("info-message") == std::string::npos) { std::cerr << "info-message missing\n"; return 1; }

    
    const int threads = 4;
    const int iters = 1000;
    std::vector<std::thread> th;
    for (int t = 0; t < threads; ++t) {
        th.emplace_back([t, iters](){
            for (int i = 0; i < iters; ++i) {
                log_info("t" + std::to_string(t) + " msg " + std::to_string(i));
            }
        });
    }
    for (auto &tt : th) tt.join();

    
    const char *tmp2 = "/tmp/logging_unit_stage2.txt";
    std::fflush(stdout);
    int saved2 = dup(fileno(stdout));
    if (saved2 == -1) { std::cerr << "dup2 failed\n"; return 1; }
    FILE *f2 = freopen(tmp2, "w+", stdout);
    if (!f2) { std::cerr << "freopen stage2 failed\n"; return 1; }

    const int single_iters = 2000;
    for (int i = 0; i < single_iters; ++i) log_info("single " + std::to_string(i));
    std::fflush(stdout);
    if (dup2(saved2, fileno(stdout)) == -1) { std::cerr << "dup2 restore stage2 failed\n"; return 1; }
    close(saved2);

    std::ifstream ifs2(tmp2);
    if (!ifs2) { std::cerr << "open tmp2 failed\n"; return 1; }
    std::string out2((std::istreambuf_iterator<char>(ifs2)), std::istreambuf_iterator<char>());
    size_t newline_count = 0;
    for (char c : out2) if (c == '\n') ++newline_count;
    if (newline_count < (size_t)single_iters) {
        std::cerr << "single-threaded expected " << single_iters << " newlines, got " << newline_count << "\n";
        return 1;
    }

    std::cout << "logging_unit ok\n";
    return 0;
}
