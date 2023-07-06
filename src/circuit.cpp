#include "lib.hpp"

using namespace nil::crypto3;

[[circuit]] bool circuit(
    std::vector<uint64_t> values,
    uint64_t expected_sum,
    typename hashes::sha2<256>::block_type expected_hash
) {
    return circuitImpl(values, expected_sum, expected_hash);
}
