#pragma once
#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

// Keccak-256 (the Ethereum variant), implemented from scratch.
//
// Needed because the on-chain KeyRegistry identifies users by
// keccak256(username) and the client must compute that locally — the
// registry check is only meaningful if the client derives everything
// itself and reads the chain directly (docs/crypto-design.md §8.11).
// libsodium provides SHA-256 but not Keccak: Ethereum's keccak256 is the
// pre-standardization Keccak with 0x01 multi-rate padding, which differs
// from standardized SHA-3's 0x06 padding and produces different digests.
//
// Verified against fixed vectors (see the test harness), including values
// observed live on-chain during backend integration:
//   keccak256("alice") = 9c0257114eb9399a2985f8e75dad7600c5d89fe3824ffa99ec1c3eb8bf3b0501
namespace keccak {

// Keccak-256 digest (rate 1088 / capacity 512 / output 256 bits).
std::array<unsigned char, 32> keccak256(const unsigned char* data, std::size_t len);
std::array<unsigned char, 32> keccak256(const std::vector<unsigned char>& data);

// Digest of a UTF-8 string, as lowercase hex without a 0x prefix.
std::string keccak256_hex(const std::string& text);

} // namespace keccak
