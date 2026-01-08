
#include <cassert>
#include <string>
#include <iostream>
#include "net/MiniJson.h"

using MinijsonIntPair = std::pair<bool,int64_t>;

void test_present_valid() {
    auto p = json_extract_int_present("{\"k\":1}", "k"); assert(p.first && p.second==1);
    p = json_extract_int_present("{ \"k\" :  -1 }", "k"); assert(p.first && p.second==-1);
    p = json_extract_int_present("{\"a\":0, \"k\": 42}", "k"); assert(p.first && p.second==42);
}

void test_present_malformed() {
    try { json_extract_int_present("{\"k\":}", "k"); assert(false); } catch(...) {}
    try { json_extract_int_present("{\"k\":-}", "k"); assert(false); } catch(...) {}
    try { json_extract_int_present("{\"k\":1x}", "k"); assert(false); } catch(...) {}
    try { json_extract_int_present("{\"k\":1 ]}", "k"); assert(false); } catch(...) {}
    try { json_extract_int_present("{\"k\":null}", "k"); assert(false); } catch(...) {}
}

void test_absent() {
    auto p = json_extract_int_present("{}", "k"); assert(p.first==false);
    auto o = json_extract_int_opt("{}", "k"); assert(!o.has_value());
}

void test_opt_behaviour() {
    auto o = json_extract_int_opt("{\"k\":  7}", "k"); assert(o.has_value() && o.value()==7);
    try { json_extract_int_opt("{\"k\":}", "k"); assert(false); } catch(...) {}
}

void test_parse_int64_strict_sv_edges() {
    using std::int64_t; using std::numeric_limits;
    auto a = parse_int64_strict_sv("-9223372036854775808"); assert(a.has_value() && *a == numeric_limits<int64_t>::min());
    auto b = parse_int64_strict_sv("9223372036854775807"); assert(b.has_value() && *b == numeric_limits<int64_t>::max());
    auto c = parse_int64_strict_sv("9223372036854775808"); assert(!c.has_value());
    auto d = parse_int64_strict_sv("-9223372036854775809"); assert(!d.has_value());
    auto e = parse_int64_strict_sv("-0"); assert(e.has_value() && *e == 0);
}

int main() {
    test_present_valid();
    test_present_malformed();
    test_absent();
    test_opt_behaviour();
    test_parse_int64_strict_sv_edges();
    std::cout << "json_parse_unit ok\n";
    return 0;
}
