#include "Chain.hpp"

#include <cstdlib>
#include <stdexcept>
#include <nlohmann/json.hpp>

#include "Crypto.hpp"   // crypto::to_base64
#include "Keccak.hpp"

using json = nlohmann::json;

// First 4 bytes of keccak256("getKey(bytes32)") — fixed by the contract
// ABI. Hardcoded constant; the Keccak implementation itself is
// vector-tested separately.
static const char* GET_KEY_SELECTOR = "12aaac70";

ChainConfig ChainConfig::from_env() {
    ChainConfig cfg;
    if (const char* url = std::getenv("SECUREMAILBOX_RPC_URL")) cfg.rpc_url = url;
    if (const char* addr = std::getenv("SECUREMAILBOX_KEY_REGISTRY")) cfg.key_registry_address = addr;
    return cfg;
}

ChainClient::ChainClient(ChainConfig config)
    : config_{std::move(config)}
    , curl_{curl_easy_init()}
{
    if (!curl_) {
        throw std::runtime_error("curl_easy_init() failed — is libcurl installed?");
    }
}

size_t ChainClient::write_callback(char* ptr, size_t size, size_t nmemb, void* userdata) {
    auto* body = static_cast<std::string*>(userdata);
    body->append(ptr, size * nmemb);
    return size * nmemb;
}

std::string ChainClient::rpc_post(const std::string& body, std::string& error) {
    std::string response;

    curl_easy_reset(curl_.get());
    curl_easy_setopt(curl_.get(), CURLOPT_URL, config_.rpc_url.c_str());
    curl_easy_setopt(curl_.get(), CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl_.get(), CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(curl_.get(), CURLOPT_POST, 1L);
    curl_easy_setopt(curl_.get(), CURLOPT_POSTFIELDS, body.c_str());
    curl_easy_setopt(curl_.get(), CURLOPT_POSTFIELDSIZE, static_cast<long>(body.size()));
    curl_easy_setopt(curl_.get(), CURLOPT_TIMEOUT, 15L);

    curl_slist* headers = curl_slist_append(nullptr, "Content-Type: application/json");
    curl_easy_setopt(curl_.get(), CURLOPT_HTTPHEADER, headers);

    const CURLcode res = curl_easy_perform(curl_.get());
    curl_slist_free_all(headers);

    if (res != CURLE_OK) {
        error = std::string("RPC unreachable: ") + curl_easy_strerror(res);
        return {};
    }
    long status = 0;
    curl_easy_getinfo(curl_.get(), CURLINFO_RESPONSE_CODE, &status);
    if (status != 200) {
        error = "RPC returned HTTP " + std::to_string(status);
        return {};
    }
    return response;
}

OnChainKey ChainClient::get_onchain_key(const std::string& username) {
    OnChainKey out;

    if (config_.key_registry_address.empty()) {
        out.reason = "KeyRegistry address not configured on this client.";
        return out;
    }

    // calldata = selector ‖ keccak256(username), all computed locally.
    const std::string data = std::string("0x") + GET_KEY_SELECTOR + keccak::keccak256_hex(username);

    const json req = {
        {"jsonrpc", "2.0"},
        {"id", 1},
        {"method", "eth_call"},
        {"params", {{{"to", config_.key_registry_address}, {"data", data}}, "latest"}},
    };

    std::string error;
    const std::string body = rpc_post(req.dump(), error);
    if (!error.empty()) {
        out.reason = error;
        return out;
    }

    try {
        const json resp = json::parse(body);
        if (resp.contains("error")) {
            out.reason = "RPC error: " + resp["error"].dump();
            return out;
        }

        std::string hex = resp.at("result").get<std::string>();
        if (hex.rfind("0x", 0) == 0) hex = hex.substr(2);

        // getKey returns (bytes32, uint32, uint64, bool): four static
        // 32-byte words, decoded by slicing — no ABI library needed.
        if (hex.size() != 4 * 64) {
            out.reason = "Unexpected eth_call result length " + std::to_string(hex.size());
            return out;
        }

        const std::string key_hex = hex.substr(0, 64);
        const unsigned version =
            static_cast<unsigned>(std::stoul(hex.substr(64, 64), nullptr, 16));
        const std::uint64_t updated_at = std::stoull(hex.substr(128, 64), nullptr, 16);
        const bool revoked = std::stoul(hex.substr(192, 64), nullptr, 16) == 1;

        out.ok = true;
        if (version == 0) {
            out.registered = false;
            return out;
        }

        std::vector<unsigned char> key_bytes(32);
        for (std::size_t i = 0; i < 32; ++i) {
            key_bytes[i] = static_cast<unsigned char>(
                std::stoul(key_hex.substr(i * 2, 2), nullptr, 16));
        }

        out.registered = true;
        out.version    = version;
        out.key_b64    = crypto::to_base64(key_bytes);
        out.updated_at = updated_at;
        out.revoked    = revoked;
        return out;
    } catch (const std::exception& e) {
        out.ok = false;
        out.reason = std::string("Failed to parse RPC response: ") + e.what();
        return out;
    }
}
