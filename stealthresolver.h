#pragma once
#include <string>
#include <vector>
#include <sstream>
#include <stdexcept>
#include <cctype>
#include <functional>
#include <iostream>

class StealthResolver {
public:
    struct T {
        std::string p;
        std::string m;
        std::vector<uint8_t> b;
    };

    static T R(std::string_view s) {
        T r;
        std::ostringstream ps, ms;
        std::vector<uint8_t> bs;

        auto proc = [](int byte, std::ostringstream& p, std::ostringstream& m, std::vector<uint8_t>& b) {
            if (byte == -1) {
                p << "\\x00";
                m << "?";
                b.push_back(0x00);
            } else {
                p << "\\x" << std::hex << (byte < 16 ? "0" : "") << byte;
                m << "x";
                b.push_back(static_cast<uint8_t>(byte));
            }
        };

        for (size_t i = 0; i < s.size(); i++) {
            if (std::isspace(s[i])) continue;

            if (s[i] == '?') {
                proc(-1, ps, ms, bs);
            } else if (i + 1 < s.size() && std::isxdigit(s[i]) && std::isxdigit(s[i + 1])) {
                proc(std::stoi(std::string{s[i], s[i + 1]}, nullptr, 16), ps, ms, bs);
                i++;
            } else {
                throw std::runtime_error("Invalid hex format in signature.");
            }
        }

        r.p = ps.str();
        r.m = ms.str();
        r.b = std::move(bs);
        return r;
    }
};

inline void OutputStealthy(const std::string& s) {
    std::for_each(s.begin(), s.end(), [](char c) { std::cout.put(c); });
}
