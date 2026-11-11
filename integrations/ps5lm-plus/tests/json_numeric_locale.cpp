// Host reproducer for the PS5 title's empty localeconv().decimal_point.
// The PS5 libc import can return a non-null but empty decimal point string;
// nlohmann's lexer must not place NUL into an otherwise valid JSON number.
#include <locale.h>
#include <algorithm>
#include <cmath>
#include <cstdio>
#include <string>
#include <utility>

#include <nlohmann/json.hpp>

#ifndef PS5LM_TEST_NORMAL_LOCALE
extern "C" struct lconv *localeconv(void) noexcept {
    static char empty[] = "";
    static struct lconv ps5_locale{};
    ps5_locale.decimal_point = empty;
    ps5_locale.thousands_sep = empty;
    return &ps5_locale;
}
#endif

int main() {
    // Fractional data is the important case; integers alone would not expose
    // the bug. Exponents exercise the same floating-point parsing branch.
    for (const auto& [input, expected] : {
             std::pair<std::string, double>{R"({"value":0.5})", 0.5},
             {R"({"value":-123.625})", -123.625},
             {R"({"value":1.25e-3})", 0.00125},
             {R"({"value":1.0e+10})", 1e10},
             {R"({"value":0.00000000000000001})", 1e-17}
         }) {
        const auto actual = nlohmann::json::parse(input).at("value").get<double>();
        if (!std::isfinite(actual) ||
            std::abs(actual - expected) > 1e-12 * std::max(std::abs(expected), 1e-12)) {
            std::fputs("numeric JSON parsing produced a wrong value\n", stderr);
            return 1;
        }
    }
    if (std::abs(nlohmann::json::parse(R"({"value":0.5})")["value"].get<double>() - 0.5) > 1e-10) {
        std::fputs("fractional JSON value was corrupted\n", stderr);
        return 1;
    }
    std::puts("empty-locale numeric JSON regression passed");
}
