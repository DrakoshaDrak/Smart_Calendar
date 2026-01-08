#include "MiniJson.h"
#include <stdexcept>
#include <cctype>
#include <vector>


std::pair<bool,std::string> json_extract_string_present(const std::string& js, const std::string& key) {
    auto p = json_extract_string_opt_present(js, key);
    if (!p.first) return {false, std::string()};
    if (!p.second.has_value()) return {true, std::string()};
    return {true, p.second.value()};
}


std::pair<bool, std::optional<std::string>> json_extract_string_opt_present(const std::string& js, const std::string& key) {
    const size_t n = js.size();
    std::vector<char> stack; 

    auto decode_string = [&](size_t start)->std::pair<std::string,size_t> {
        
        std::string out;
        size_t i = start;
        for (;; ++i) {
            if (i >= n) throw std::runtime_error("unterminated json string");
            char c = js[i];
            if (c == '"') return {out, i};
            if (c == '\\') {
                if (i + 1 >= n) throw std::runtime_error("unterminated escape in json string");
                char e = js[i+1];
                switch (e) {
                    case '"': out.push_back('"'); break;
                    case '\\': out.push_back('\\'); break;
                    case 'n': out.push_back('\n'); break;
                    case 'r': out.push_back('\r'); break;
                    case 't': out.push_back('\t'); break;
                    case '/': out.push_back('/'); break;
                    case 'b': out.push_back('\b'); break;
                    case 'f': out.push_back('\f'); break;
                    case 'u': {
                        // support basic \uXXXX (BMP only)
                        if (i + 5 >= n) throw std::runtime_error("invalid unicode escape in json string");
                        int code = 0;
                        for (size_t k = i+2; k <= i+5; ++k) {
                            char ch = js[k];
                            code <<= 4;
                            if (ch >= '0' && ch <= '9') code += ch - '0';
                            else if (ch >= 'a' && ch <= 'f') code += 10 + (ch - 'a');
                            else if (ch >= 'A' && ch <= 'F') code += 10 + (ch - 'A');
                            else throw std::runtime_error("invalid hex in unicode escape");
                        }
                        if (code <= 0x7f) out.push_back((char)code);
                        else if (code <= 0x7ff) {
                            out.push_back((char)(0xc0 | ((code >> 6) & 0x1f)));
                            out.push_back((char)(0x80 | (code & 0x3f)));
                        } else {
                            out.push_back((char)(0xe0 | ((code >> 12) & 0x0f)));
                            out.push_back((char)(0x80 | ((code >> 6) & 0x3f)));
                            out.push_back((char)(0x80 | (code & 0x3f)));
                        }
                        i += 5; // consumed \uXXXX (i will be incremented by loop)
                        break;
                    }
                    default: throw std::runtime_error("unsupported escape in json string");
                }
                ++i; // skip escape char
                continue;
            }
            out.push_back(c);
        }
    };

    for (size_t i = 0; i < n; ++i) {
        char c = js[i];
        if (c == '"') {
            // decode string at i+1
            auto dec = decode_string(i+1);
            const std::string& decoded = dec.first;
            size_t closing = dec.second; // index of closing '"'

            // determine if this string is a key candidate: previous non-space char is '{' or ','
            size_t before = i;
            while (before > 0 && isspace((unsigned char)js[before-1])) --before;
            bool prev_obj_or_comma = (before > 0 && (js[before-1] == '{' || js[before-1] == ','));

            // next non-space char after closing quote
            size_t after = closing + 1;
            while (after < n && isspace((unsigned char)js[after])) ++after;

            bool in_object = (!stack.empty() && stack.back() == '{');
            bool key_candidate = in_object && prev_obj_or_comma;

            if (key_candidate && after < n && js[after] == ':') {
                // we found a key; check match
                if (decoded == key) {
                    // parse value after ':'
                    size_t valpos = after + 1;
                    while (valpos < n && isspace((unsigned char)js[valpos])) ++valpos;
                    if (valpos >= n) throw std::runtime_error("missing value for string field");
                    if (js.compare(valpos, 4, "null") == 0) return {true, std::nullopt};
                    if (js[valpos] != '"') throw std::runtime_error("invalid type for json string field");
                    auto val_dec = decode_string(valpos+1);
                    return {true, val_dec.first};
                }
            } else if (prev_obj_or_comma && after < n && js[after] != ':') {
                // If this looks like a key position but there's no colon, that's malformed only when inside an object
                if (in_object) throw std::runtime_error("missing ':' after string field");
                // otherwise it's likely an array or other context (e.g. ["a","b"]) — not an error
            }

            // advance i to closing quote
            i = closing;
            continue;
        }

        // track nesting when outside strings
        if (c == '{' || c == '[') { stack.push_back(c); }
        else if (c == '}' || c == ']') { if (!stack.empty()) stack.pop_back(); }
    }

    return {false, std::nullopt};
}
// Use scanner approach similar to string extractor to avoid matching inside strings
std::pair<bool,int64_t> json_extract_int_present(const std::string& js, const std::string& key) {
    const size_t n = js.size();
    std::vector<char> stack;

    // Reuse decode_string logic for key decoding
    auto decode_string = [&](size_t start)->std::pair<std::string,size_t> {
        // start points to the first character AFTER the opening '"'
        std::string out;
        size_t i = start;
        for (;; ++i) {
            if (i >= n) throw std::runtime_error("unterminated json string");
            char c = js[i];
            if (c == '"') return {out, i};
            if (c == '\\') {
                if (i + 1 >= n) throw std::runtime_error("unterminated escape in json string");
                char e = js[i+1];
                switch (e) {
                    case '"': out.push_back('"'); break;
                    case '\\': out.push_back('\\'); break;
                    case 'n': out.push_back('\n'); break;
                    case 'r': out.push_back('\r'); break;
                    case 't': out.push_back('\t'); break;
                    case '/': out.push_back('/'); break;
                    case 'b': out.push_back('\b'); break;
                    case 'f': out.push_back('\f'); break;
                    case 'u': {
                        if (i + 5 >= n) throw std::runtime_error("invalid unicode escape in json string");
                        int code = 0;
                        for (size_t k = i+2; k <= i+5; ++k) {
                            char ch = js[k];
                            code <<= 4;
                            if (ch >= '0' && ch <= '9') code += ch - '0';
                            else if (ch >= 'a' && ch <= 'f') code += 10 + (ch - 'a');
                            else if (ch >= 'A' && ch <= 'F') code += 10 + (ch - 'A');
                            else throw std::runtime_error("invalid hex in unicode escape");
                        }
                        if (code <= 0x7f) out.push_back((char)code);
                        else if (code <= 0x7ff) {
                            out.push_back((char)(0xc0 | ((code >> 6) & 0x1f)));
                            out.push_back((char)(0x80 | (code & 0x3f)));
                        } else {
                            out.push_back((char)(0xe0 | ((code >> 12) & 0x0f)));
                            out.push_back((char)(0x80 | ((code >> 6) & 0x3f)));
                            out.push_back((char)(0x80 | (code & 0x3f)));
                        }
                        i += 5; // consumed \uXXXX
                        break;
                    }
                    default: throw std::runtime_error("unsupported escape in json string");
                }
                ++i; // skip escape char
                continue;
            }
            out.push_back(c);
        }
    };

    for (size_t i = 0; i < n; ++i) {
        char c = js[i];
        if (c == '"') {
            // decode the quoted string at i+1 (decode_string returns decoded value and closing index)
            auto dec0 = decode_string(i+1);
            const std::string& decoded = dec0.first;
            size_t closing = dec0.second;
            // check if this string is a key candidate
            size_t before = i;
            while (before > 0 && isspace((unsigned char)js[before-1])) --before;
            bool prev_obj_or_comma = (before > 0 && (js[before-1] == '{' || js[before-1] == ','));
            size_t after = closing + 1; while (after < n && isspace((unsigned char)js[after])) ++after;
                    if (prev_obj_or_comma && after < n && js[after] == ':' && !stack.empty() && stack.back() == '{') {
                    // compare decoded key against requested key
                    if (decoded == key) {
                    // parse the value after ':'
                    size_t valpos = after + 1; while (valpos < n && isspace((unsigned char)js[valpos])) ++valpos;
                    if (valpos >= n) throw std::runtime_error("missing int value");
                    if (js.compare(valpos, 4, "null") == 0) throw std::runtime_error("null not allowed for integer field");
                    size_t end = valpos; if (end < n && js[end] == '-') ++end; while (end < n && js[end] >= '0' && js[end] <= '9') ++end;
                    if (end == valpos || (end == valpos+1 && js[valpos] == '-')) throw std::runtime_error("invalid json int");
                    size_t after_tok = end; while (after_tok < n && isspace((unsigned char)js[after_tok])) ++after_tok;
                    if (after_tok >= n || (js[after_tok] != ',' && js[after_tok] != '}')) throw std::runtime_error("invalid json int terminator");
                    auto sv = std::string_view(js).substr(valpos, end - valpos);
                    auto parsed = parse_int64_strict_sv(sv);
                    if (!parsed.has_value()) throw std::runtime_error("invalid json int value");
                    return {true, *parsed};
                }
            }
            i = closing;
            continue;
        }
        if (c == '{' || c == '[') stack.push_back(c);
        else if (c == '}' || c == ']') if (!stack.empty()) stack.pop_back();
    }
    return {false, 0};
}

// non-present variant: returns empty string on not-found or explicit null
std::string json_extract_string(const std::string& js, const std::string& key) {
    auto pr = json_extract_string_opt_present(js, key);
    if (!pr.first) return std::string();
    if (!pr.second.has_value()) return std::string();
    return pr.second.value();
}

std::optional<int64_t> json_extract_int_opt(const std::string& js, const std::string& key) {
    const size_t n = js.size();
    std::vector<char> stack;

    auto decode_string = [&](size_t start)->std::pair<std::string,size_t> {
        std::string out;
        size_t i = start;
        for (;; ++i) {
            if (i >= n) throw std::runtime_error("unterminated json string");
            char c = js[i];
            if (c == '"') return {out, i};
            if (c == '\\') {
                if (i + 1 >= n) throw std::runtime_error("unterminated escape in json string");
                char e = js[i+1];
                switch (e) {
                    case '"': out.push_back('"'); break;
                    case '\\': out.push_back('\\'); break;
                    case 'n': out.push_back('\n'); break;
                    case 'r': out.push_back('\r'); break;
                    case 't': out.push_back('\t'); break;
                    case '/': out.push_back('/'); break;
                    case 'b': out.push_back('\b'); break;
                    case 'f': out.push_back('\f'); break;
                    case 'u': {
                        if (i + 5 >= n) throw std::runtime_error("invalid unicode escape in json string");
                        int code = 0;
                        for (size_t k = i+2; k <= i+5; ++k) {
                            char ch = js[k];
                            code <<= 4;
                            if (ch >= '0' && ch <= '9') code += ch - '0';
                            else if (ch >= 'a' && ch <= 'f') code += 10 + (ch - 'a');
                            else if (ch >= 'A' && ch <= 'F') code += 10 + (ch - 'A');
                            else throw std::runtime_error("invalid hex in unicode escape");
                        }
                        if (code <= 0x7f) out.push_back((char)code);
                        else if (code <= 0x7ff) {
                            out.push_back((char)(0xc0 | ((code >> 6) & 0x1f)));
                            out.push_back((char)(0x80 | (code & 0x3f)));
                        } else {
                            out.push_back((char)(0xe0 | ((code >> 12) & 0x0f)));
                            out.push_back((char)(0x80 | ((code >> 6) & 0x3f)));
                            out.push_back((char)(0x80 | (code & 0x3f)));
                        }
                        i += 5; // consumed \uXXXX
                        break;
                    }
                    default: throw std::runtime_error("unsupported escape in json string");
                }
                ++i; // skip escape char
                continue;
            }
            out.push_back(c);
        }
    };

    for (size_t i = 0; i < n; ++i) {
        char c = js[i];
        if (c == '"') {
            // decode quoted string immediately
            auto dec0 = decode_string(i+1);
            const std::string& decoded = dec0.first;
            size_t closing = dec0.second;
            size_t before = i;
            while (before > 0 && isspace((unsigned char)js[before-1])) --before;
            bool prev_obj_or_comma = (before > 0 && (js[before-1] == '{' || js[before-1] == ','));
            size_t after = closing + 1; while (after < n && isspace((unsigned char)js[after])) ++after;
            if (prev_obj_or_comma && after < n && js[after] == ':' && !stack.empty() && stack.back() == '{') {
                std::string key_found = decoded;
                if (key_found == key) {
                    size_t valpos = after + 1; while (valpos < n && isspace((unsigned char)js[valpos])) ++valpos;
                    if (valpos >= n) throw std::runtime_error("missing int value");
                    if (js.compare(valpos, 4, "null") == 0) throw std::runtime_error("null not allowed for integer field");
                    size_t end = valpos; if (end < n && js[end] == '-') ++end; while (end < n && js[end] >= '0' && js[end] <= '9') ++end;
                    if (end == valpos || (end == valpos+1 && js[valpos] == '-')) throw std::runtime_error("invalid json int");
                    size_t after_tok = end; while (after_tok < n && isspace((unsigned char)js[after_tok])) ++after_tok;
                    if (after_tok >= n || (js[after_tok] != ',' && js[after_tok] != '}')) throw std::runtime_error("invalid json int terminator");
                    auto sv = std::string_view(js).substr(valpos, end - valpos);
                    auto parsed = parse_int64_strict_sv(sv);
                    if (!parsed.has_value()) throw std::runtime_error("invalid json int value");
                    return std::optional<int64_t>(*parsed);
                }
            }
            i = closing;
            continue;
        }
        if (c == '{' || c == '[') stack.push_back(c);
        else if (c == '}' || c == ']') if (!stack.empty()) stack.pop_back();
    }
    return std::nullopt;
}

// escape chars for JSON response strings; escapes control chars < 0x20 with \u00XX
std::string json_escape_resp(const std::string& s) {
    static const char* hex = "0123456789ABCDEF";
    std::string out; out.reserve(s.size()+8);
    for (unsigned char uc : s) {
        if (uc == '"') { out += "\\\""; }
        else if (uc == '\\') { out += "\\\\"; }
        else if (uc == '\n') { out += "\\n"; }
        else if (uc == '\r') { out += "\\r"; }
        else if (uc == '\t') { out += "\\t"; }
        else if (uc < 0x20) {
            out.push_back('\\'); out.push_back('u'); out.push_back('0'); out.push_back('0');
            out.push_back(hex[(uc >> 4) & 0xF]); out.push_back(hex[uc & 0xF]);
        } else out.push_back((char)uc);
    }
    return out;
}

static bool is_int_strict(const std::string& s) {
    if (s.empty()) return false;
    size_t i = 0;
    if (s[0] == '-') { if (s.size() == 1) return false; i = 1; }
    for (; i < s.size(); ++i) if (s[i] < '0' || s[i] > '9') return false;
    return true;
}

std::string json_emit_int(const std::optional<std::string>& o, int64_t fallback) {
    if (!o.has_value() || o->empty() || !is_int_strict(*o)) return std::to_string(fallback);
    return *o;
}

std::string json_emit_int_or_null(const std::optional<std::string>& o) {
    if (!o.has_value() || o->empty() || !is_int_strict(*o)) return std::string("null");
    return *o;
}

std::string json_emit_int32(const std::optional<std::string>& o, int fallback) {
    if (!o.has_value() || o->empty() || !is_int_strict(*o)) return std::to_string(fallback);
    auto parsed = json_parse_int_strict(o);
    if (!parsed.has_value()) return std::to_string(fallback);
    int64_t v = *parsed;
    if (v < std::numeric_limits<int>::min() || v > std::numeric_limits<int>::max()) return std::to_string(fallback);
    return std::to_string(static_cast<int>(v));
}

std::optional<int64_t> json_parse_int_strict(const std::optional<std::string>& o) {
    if (!o.has_value() || o->empty() || !is_int_strict(*o)) return std::nullopt;
    return parse_int64_strict_sv(std::string_view(*o));
}
