#pragma once
#include <cstdint>
#include <memory>
#include <string>
#include <curl/curl.h>

// ChainClient — direct client → Sepolia reads of the KeyRegistry contract.
//
// SECURITY MODEL (docs/crypto-design.md §3(d)1, §8.11): the client side of
// the on-chain key-transparency check. The identity hash (keccak256 of the
// username), the calldata, and the result decode are all computed locally,
// and the JSON-RPC request goes straight to a public Sepolia endpoint —
// never through the mailbox server. Routing the lookup through the server
// would let a compromised server answer its own integrity check, which is
// exactly the attack the registry exists to expose.
//
// Failure semantics are the caller's job: the pre-encrypt gate must FAIL
// CLOSED on any RPC failure (an active network attacker who can block the
// RPC must not silently disable the check). get_onchain_key() therefore
// never hides errors — every result carries an explicit ok/error status.
//
// The default RPC endpoint is a public, keyless Sepolia node
// (publicnode.com): nothing secret to embed in a distributed binary, at
// the cost of public-endpoint rate limits (recorded as a known limitation
// in the design doc). Overridable via SECUREMAILBOX_RPC_URL /
// SECUREMAILBOX_KEY_REGISTRY for local integration testing.

struct ChainConfig {
    std::string rpc_url{"https://ethereum-sepolia-rpc.publicnode.com"};
    // Live KeyRegistry deployment on Sepolia (docs/deployment.md). Override
    // via SECUREMAILBOX_KEY_REGISTRY (e.g. a local Hardhat node for tests).
    // Empty = unconfigured; lookups report an error (callers fail closed).
    std::string key_registry_address{"0x230c56Ab59535625c8eAeF18f8394b7D222a889D"};

    // Apply SECUREMAILBOX_RPC_URL / SECUREMAILBOX_KEY_REGISTRY env overrides.
    static ChainConfig from_env();
};

struct OnChainKey {
    bool        ok{false};        // false → `reason` explains; callers fail closed
    std::string reason;           // set when !ok

    bool        registered{false};
    unsigned    version{0};
    std::string key_b64;          // base64 of the 32-byte X25519 key (when registered)
    std::uint64_t updated_at{0};  // unix timestamp (when registered)
    bool        revoked{false};
};

class ChainClient {
public:
    explicit ChainClient(ChainConfig config = ChainConfig::from_env());

    ~ChainClient() = default;
    ChainClient(const ChainClient&)            = delete;
    ChainClient& operator=(const ChainClient&) = delete;
    ChainClient(ChainClient&&)                 = default;
    ChainClient& operator=(ChainClient&&)      = default;

    // KeyRegistry.getKey(keccak256(username)) via eth_call.
    OnChainKey get_onchain_key(const std::string& username);

    const ChainConfig& config() const noexcept { return config_; }

private:
    struct CurlDeleter {
        void operator()(CURL* c) const noexcept { curl_easy_cleanup(c); }
    };
    using CurlHandle = std::unique_ptr<CURL, CurlDeleter>;

    // POST a JSON-RPC body; returns the raw response body or nullopt-like
    // empty string with `error` set.
    std::string rpc_post(const std::string& body, std::string& error);

    static size_t write_callback(char* ptr, size_t size, size_t nmemb, void* userdata);

    ChainConfig config_;
    CurlHandle  curl_;
};
