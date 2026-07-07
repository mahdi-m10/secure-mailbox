#include "KeyVault.hpp"
#include <fstream>
#include <iostream>
#include <sodium.h>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

namespace {

// Read and parse the vault file; nullopt if missing or malformed.
std::optional<json> read_vault_json(const std::filesystem::path& path) {
    std::ifstream in(path);
    if (!in) return std::nullopt;
    try {
        json j;
        in >> j;
        return j;
    } catch (const std::exception& e) {
        std::cerr << "Vault file is corrupt: " << e.what() << "\n";
        return std::nullopt;
    }
}

// Argon2id passphrase → 32-byte secretbox key, using the vault's stored
// parameters so old vaults keep opening if the defaults ever change.
std::optional<crypto::Bytes> derive_wrap_key(const std::string& passphrase,
                                             const crypto::Bytes& salt,
                                             unsigned long long opslimit,
                                             std::size_t memlimit) {
    if (salt.size() != crypto_pwhash_SALTBYTES) return std::nullopt;
    crypto::Bytes key(crypto_secretbox_KEYBYTES); // 32
    if (crypto_pwhash(key.data(), key.size(),
                      passphrase.c_str(), passphrase.size(),
                      salt.data(),
                      opslimit, memlimit,
                      crypto_pwhash_ALG_ARGON2ID13) != 0) {
        // Only fails on out-of-memory for the Argon2 work area.
        std::cerr << "Argon2id derivation failed (out of memory?)\n";
        return std::nullopt;
    }
    return key;
}

} // namespace

bool KeyVault::create(const crypto::Keypair& kp, const std::string& passphrase) const {
    if (exists()) {
        std::cerr << "Refusing to overwrite existing vault: " << path_ << "\n";
        return false;
    }
    if (kp.priv.size() != crypto_box_SECRETKEYBYTES ||
        kp.pub.size()  != crypto_box_PUBLICKEYBYTES) {
        std::cerr << "Keypair must be 32+32 bytes.\n";
        return false;
    }

    crypto::Bytes salt(crypto_pwhash_SALTBYTES);
    randombytes_buf(salt.data(), salt.size());

    const unsigned long long opslimit = crypto_pwhash_OPSLIMIT_MODERATE;
    const std::size_t        memlimit = crypto_pwhash_MEMLIMIT_MODERATE;

    auto wrap_key = derive_wrap_key(passphrase, salt, opslimit, memlimit);
    if (!wrap_key) return false;

    crypto::Bytes nonce(crypto_secretbox_NONCEBYTES); // 24 — random is safe at this size
    randombytes_buf(nonce.data(), nonce.size());

    crypto::Bytes boxed(kp.priv.size() + crypto_secretbox_MACBYTES);
    crypto_secretbox_easy(boxed.data(),
                          kp.priv.data(), kp.priv.size(),
                          nonce.data(), wrap_key->data());
    sodium_memzero(wrap_key->data(), wrap_key->size());

    json j = {
        {"version",               1},
        {"kdf",                   "argon2id13"},
        {"opslimit",              opslimit},
        {"memlimit_bytes",        memlimit},
        {"salt",                  crypto::to_base64(salt)},
        {"nonce",                 crypto::to_base64(nonce)},
        {"public_key",            crypto::to_base64(kp.pub)},
        {"encrypted_private_key", crypto::to_base64(boxed)},
    };

    std::error_code ec;
    std::filesystem::create_directories(path_.parent_path(), ec);

    {
        std::ofstream out(path_, std::ios::trunc);
        if (!out) {
            std::cerr << "Cannot write vault file: " << path_ << "\n";
            return false;
        }
        out << j.dump(2) << "\n";
    }

    // Owner read/write only — the vault holds wrapped key material.
    std::filesystem::permissions(path_,
        std::filesystem::perms::owner_read | std::filesystem::perms::owner_write,
        std::filesystem::perm_options::replace, ec);
    if (ec) std::cerr << "Warning: could not set vault permissions to 0600.\n";

    return true;
}

std::optional<crypto::Keypair> KeyVault::unlock(const std::string& passphrase) const {
    auto j_opt = read_vault_json(path_);
    if (!j_opt) return std::nullopt;
    const json& j = *j_opt;

    try {
        if (j.at("version").get<int>() != 1 ||
            j.at("kdf").get<std::string>() != "argon2id13") {
            std::cerr << "Unsupported vault version/KDF.\n";
            return std::nullopt;
        }

        const auto salt  = crypto::from_base64(j.at("salt").get<std::string>());
        const auto nonce = crypto::from_base64(j.at("nonce").get<std::string>());
        const auto boxed = crypto::from_base64(j.at("encrypted_private_key").get<std::string>());
        const auto pub   = crypto::from_base64(j.at("public_key").get<std::string>());

        if (nonce.size() != crypto_secretbox_NONCEBYTES ||
            boxed.size() != crypto_box_SECRETKEYBYTES + crypto_secretbox_MACBYTES) {
            std::cerr << "Vault fields have unexpected sizes.\n";
            return std::nullopt;
        }

        auto wrap_key = derive_wrap_key(passphrase,
                                        salt,
                                        j.at("opslimit").get<unsigned long long>(),
                                        j.at("memlimit_bytes").get<std::size_t>());
        if (!wrap_key) return std::nullopt;

        crypto::Keypair kp;
        kp.pub = pub;
        kp.priv.resize(crypto_box_SECRETKEYBYTES);
        const int rc = crypto_secretbox_open_easy(
            kp.priv.data(), boxed.data(), boxed.size(),
            nonce.data(), wrap_key->data());
        sodium_memzero(wrap_key->data(), wrap_key->size());

        if (rc != 0) {
            // Poly1305 MAC failure — wrong passphrase (or tampered file).
            sodium_memzero(kp.priv.data(), kp.priv.size());
            return std::nullopt;
        }
        return kp;
    } catch (const std::exception& e) {
        std::cerr << "Vault file is corrupt: " << e.what() << "\n";
        return std::nullopt;
    }
}

std::optional<std::string> KeyVault::public_key_b64() const {
    auto j_opt = read_vault_json(path_);
    if (!j_opt) return std::nullopt;
    try {
        return j_opt->at("public_key").get<std::string>();
    } catch (...) {
        return std::nullopt;
    }
}
