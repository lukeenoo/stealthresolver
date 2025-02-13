#include <iostream>

int main() {
    try {
        //example sig ofc
        constexpr auto signature = "48 8B 05 ? ? ? ? 48 85 C0 74";
        auto result = StealthResolver::R(signature);

        OutputStealthy("Pattern: " + result.p + "\n");
        OutputStealthy("Mask:    " + result.m + "\n");
        OutputStealthy("Bytes:   ");

        for (auto byte : result.b) {
            OutputStealthy(std::to_string(static_cast<int>(byte)) + " ");
        }
        OutputStealthy("\n");
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << '\n';
    }
    return 0;
}
