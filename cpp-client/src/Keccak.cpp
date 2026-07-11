#include "Keccak.hpp"

namespace keccak {

namespace {

constexpr std::size_t RATE_BYTES = 136;  // 1088-bit rate for Keccak-256

constexpr std::uint64_t RC[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL,
    0x8000000080008000ULL, 0x000000000000808bULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008aULL,
    0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL,
    0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800aULL, 0x800000008000000aULL, 0x8000000080008081ULL,
    0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL,
};

// Rotation offsets indexed [x][y], per the Keccak reference.
constexpr int RHO[5][5] = {
    {0, 36, 3, 41, 18},
    {1, 44, 10, 45, 2},
    {62, 6, 43, 15, 61},
    {28, 55, 25, 21, 56},
    {27, 20, 39, 8, 14},
};

inline std::uint64_t rotl64(std::uint64_t v, int n) {
    return n == 0 ? v : (v << n) | (v >> (64 - n));
}

// One Keccak-f[1600] permutation over the 5×5 lane state (index x + 5y).
void keccak_f(std::uint64_t s[25]) {
    for (int round = 0; round < 24; ++round) {
        // θ
        std::uint64_t c[5];
        for (int x = 0; x < 5; ++x)
            c[x] = s[x] ^ s[x + 5] ^ s[x + 10] ^ s[x + 15] ^ s[x + 20];
        for (int x = 0; x < 5; ++x) {
            const std::uint64_t d = c[(x + 4) % 5] ^ rotl64(c[(x + 1) % 5], 1);
            for (int y = 0; y < 5; ++y) s[x + 5 * y] ^= d;
        }

        // ρ + π
        std::uint64_t b[25];
        for (int x = 0; x < 5; ++x)
            for (int y = 0; y < 5; ++y)
                b[y + 5 * ((2 * x + 3 * y) % 5)] = rotl64(s[x + 5 * y], RHO[x][y]);

        // χ
        for (int x = 0; x < 5; ++x)
            for (int y = 0; y < 5; ++y)
                s[x + 5 * y] = b[x + 5 * y] ^ (~b[(x + 1) % 5 + 5 * y] & b[(x + 2) % 5 + 5 * y]);

        // ι
        s[0] ^= RC[round];
    }
}

} // namespace

std::array<unsigned char, 32> keccak256(const unsigned char* data, std::size_t len) {
    std::uint64_t state[25] = {0};

    // Keccak (pre-SHA-3) multi-rate padding: 0x01 ... 0x80.
    const std::size_t blocks = (len + 1 + RATE_BYTES - 1) / RATE_BYTES;
    std::vector<unsigned char> padded(blocks * RATE_BYTES, 0);
    for (std::size_t i = 0; i < len; ++i) padded[i] = data[i];
    padded[len] = 0x01;
    padded[padded.size() - 1] |= 0x80;

    // Absorb (lanes are little-endian u64).
    for (std::size_t off = 0; off < padded.size(); off += RATE_BYTES) {
        for (std::size_t i = 0; i < RATE_BYTES / 8; ++i) {
            std::uint64_t lane = 0;
            for (int b = 7; b >= 0; --b)
                lane = (lane << 8) | padded[off + i * 8 + static_cast<std::size_t>(b)];
            state[i] ^= lane;
        }
        keccak_f(state);
    }

    // Squeeze: 32 bytes = the first 4 lanes.
    std::array<unsigned char, 32> out{};
    for (int i = 0; i < 4; ++i) {
        std::uint64_t lane = state[i];
        for (int b = 0; b < 8; ++b) {
            out[static_cast<std::size_t>(i * 8 + b)] = static_cast<unsigned char>(lane & 0xff);
            lane >>= 8;
        }
    }
    return out;
}

std::array<unsigned char, 32> keccak256(const std::vector<unsigned char>& data) {
    return keccak256(data.data(), data.size());
}

std::string keccak256_hex(const std::string& text) {
    const auto digest =
        keccak256(reinterpret_cast<const unsigned char*>(text.data()), text.size());
    static const char* hexdig = "0123456789abcdef";
    std::string out;
    out.reserve(64);
    for (unsigned char byte : digest) {
        out.push_back(hexdig[byte >> 4]);
        out.push_back(hexdig[byte & 0x0f]);
    }
    return out;
}

} // namespace keccak
