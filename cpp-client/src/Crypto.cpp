#include "Crypto.hpp"
#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <sodium.h>

namespace crypto {

// ── Base64 ────────────────────────────────────────────────────────────────────

std::string to_base64(const unsigned char* data, std::size_t len) {
    const std::size_t b64_len =
        sodium_base64_encoded_len(len, sodium_base64_VARIANT_ORIGINAL);
    std::string result(b64_len, '\0');
    sodium_bin2base64(result.data(), b64_len, data, len,
                      sodium_base64_VARIANT_ORIGINAL);
    result.resize(b64_len - 1);  // drop null terminator sodium includes in the count
    return result;
}

std::string to_base64(const Bytes& v) {
    return to_base64(v.data(), v.size());
}

Bytes from_base64(const std::string& b64) {
    Bytes bin(b64.size());
    std::size_t bin_len = 0;
    if (sodium_base642bin(bin.data(), bin.size(),
                          b64.c_str(), b64.size(),
                          nullptr, &bin_len, nullptr,
                          sodium_base64_VARIANT_ORIGINAL) != 0) {
        throw std::runtime_error("Invalid base64: " + b64.substr(0, 32) + "…");
    }
    bin.resize(bin_len);
    return bin;
}

// ── Keypair ───────────────────────────────────────────────────────────────────

Keypair generate_keypair() {
    Keypair kp;
    kp.pub.resize(crypto_box_PUBLICKEYBYTES);   // 32
    kp.priv.resize(crypto_box_SECRETKEYBYTES);  // 32
    crypto_box_keypair(kp.pub.data(), kp.priv.data());
    return kp;
}

std::string key_fingerprint(const std::string& key_b64) {
    const Bytes key = from_base64(key_b64);
    unsigned char digest[crypto_hash_sha256_BYTES];
    crypto_hash_sha256(digest, key.data(), key.size());

    std::ostringstream out;
    out << std::hex << std::setfill('0');
    for (std::size_t i = 0; i < sizeof(digest); ++i) {
        if (i > 0 && i % 4 == 0) out << ' ';   // 4 bytes = 8 hex chars per group
        out << std::setw(2) << static_cast<int>(digest[i]);
    }
    return out.str();
}

// ── Canonical file-context AAD ────────────────────────────────────────────────

std::string build_file_aad(const std::string& sender_username,
                           const std::string& recipient_username,
                           const std::string& filename)
{
    return "smx:v1:sender=" + sender_username +
           ":recipient="    + recipient_username +
           ":filename="     + filename;
}

// ── HKDF-SHA256 (RFC 5869) ────────────────────────────────────────────────────
//
// Implemented from libsodium's HMAC-SHA256 primitives.  Reproduces identical
// output to Python's HKDF(SHA256, length, salt, info).derive(ikm).

// HKDF-Extract: PRK = HMAC-SHA256(key=salt, data=ikm)
static Bytes hkdf_extract(const Bytes& salt, const Bytes& ikm) {
    Bytes prk(crypto_auth_hmacsha256_BYTES); // 32
    crypto_auth_hmacsha256_state st;
    crypto_auth_hmacsha256_init  (&st, salt.data(), salt.size());
    crypto_auth_hmacsha256_update(&st, ikm.data(),  ikm.size());
    crypto_auth_hmacsha256_final (&st, prk.data());
    return prk;
}

// HKDF-Expand: OKM = T(1) ‖ T(2) ‖ … truncated to `length` bytes.
//   T(0) = ""
//   T(i) = HMAC-SHA256(PRK, T(i-1) ‖ info ‖ i)
static Bytes hkdf_expand(const Bytes& prk, const Bytes& info, std::size_t length) {
    const std::size_t H = crypto_auth_hmacsha256_BYTES; // 32
    Bytes okm;
    okm.reserve(length + H);
    Bytes t_prev; // T(i-1), empty for first round
    unsigned char counter = 0;
    while (okm.size() < length) {
        ++counter;
        crypto_auth_hmacsha256_state st;
        crypto_auth_hmacsha256_init(&st, prk.data(), prk.size());
        if (!t_prev.empty())
            crypto_auth_hmacsha256_update(&st, t_prev.data(), t_prev.size());
        if (!info.empty())
            crypto_auth_hmacsha256_update(&st, info.data(), info.size());
        crypto_auth_hmacsha256_update(&st, &counter, 1);
        t_prev.resize(H);
        crypto_auth_hmacsha256_final(&st, t_prev.data());
        okm.insert(okm.end(), t_prev.begin(), t_prev.end());
    }
    okm.resize(length);
    return okm;
}

// ── HPKE Mode_Auth ────────────────────────────────────────────────────────────

EncryptedFile hpke_encapsulate(const Bytes& plaintext,
                               const Bytes& recipient_pub,
                               const Bytes& sender_priv,
                               const std::string& aad,
                               const Bytes& info)
{
    if (recipient_pub.size() != 32)
        throw std::runtime_error("recipient_pub must be 32 bytes");
    if (sender_priv.size() != 32)
        throw std::runtime_error("sender_priv must be 32 bytes");

    // 1. Generate ephemeral X25519 keypair.
    //    ek_priv is used for one DH computation and then zeroed — it never
    //    leaves this function and does not appear in the output.
    Bytes ek_priv(32), ek_pub(32);
    randombytes_buf(ek_priv.data(), 32);
    crypto_scalarmult_curve25519_base(ek_pub.data(), ek_priv.data());

    // 2. Two DH computations — the core of Mode_Auth.
    //    crypto_scalarmult_curve25519 applies Curve25519 clamping internally,
    //    identical to Python's X25519PrivateKey.exchange() behaviour.
    Bytes dh1(32), dh2(32);
    if (crypto_scalarmult_curve25519(dh1.data(), ek_priv.data(),     recipient_pub.data()) != 0 ||
        crypto_scalarmult_curve25519(dh2.data(), sender_priv.data(), recipient_pub.data()) != 0) {
        sodium_memzero(ek_priv.data(), ek_priv.size());
        throw std::runtime_error("DH computation failed — low-order point?");
    }

    // 3. HKDF-SHA256 key schedule (identical to Python's _derive_key_and_nonce).
    //    ikm  = dh1 ‖ dh2
    //    salt = ek_pub  (binds derivation to this specific encapsulation)
    //    OKM  = 44 bytes: key = OKM[0:32], nonce = OKM[32:44]
    Bytes ikm;
    ikm.insert(ikm.end(), dh1.begin(), dh1.end());
    ikm.insert(ikm.end(), dh2.begin(), dh2.end());
    auto prk = hkdf_extract(ek_pub, ikm);
    auto okm = hkdf_expand(prk, info, 44);

    Bytes aes_key(okm.begin(),      okm.begin() + 32);
    Bytes nonce  (okm.begin() + 32, okm.begin() + 44);

    // 4. AES-256-GCM encrypt (matches Python AESGCM(key).encrypt(nonce, pt, aad)).
    const auto* ad = aad.empty() ? nullptr
                                 : reinterpret_cast<const unsigned char*>(aad.data());
    Bytes ct(plaintext.size() + crypto_aead_aes256gcm_ABYTES);
    unsigned long long ct_len = 0;
    crypto_aead_aes256gcm_encrypt(
        ct.data(), &ct_len,
        plaintext.data(), plaintext.size(),
        ad, aad.size(),  // associated data — authenticated, not encrypted
        nullptr,         // nsec — unused
        nonce.data(), aes_key.data());
    ct.resize(ct_len);

    // 5. Zero all sensitive intermediate values before they leave the stack.
    sodium_memzero(ek_priv.data(), ek_priv.size());
    sodium_memzero(ikm.data(),     ikm.size());
    sodium_memzero(dh1.data(),     dh1.size());
    sodium_memzero(dh2.data(),     dh2.size());
    sodium_memzero(prk.data(),     prk.size());
    sodium_memzero(okm.data(),     okm.size());
    sodium_memzero(aes_key.data(), aes_key.size());

    // encrypted_key carries the ephemeral public key (ek_pub), not a wrapped
    // message key.  The recipient re-derives the actual symmetric key via HKDF.
    return EncryptedFile{to_base64(ct), to_base64(nonce), to_base64(ek_pub)};
}

std::optional<Bytes> hpke_decapsulate(const std::string& ciphertext_blob_b64,
                                      const std::string& enc_key_b64,
                                      const Bytes& recipient_priv,
                                      const Bytes& sender_pub,
                                      const std::string& aad,
                                      const Bytes& info)
{
    try {
        // Unpack the server blob: nonce_12 ‖ ciphertext_with_tag.
        auto blob   = from_base64(ciphertext_blob_b64);
        auto ek_pub = from_base64(enc_key_b64);

        if (ek_pub.size() != 32) {
            std::cerr << "enc_key must be 32 bytes (X25519 ek_pub); got "
                      << ek_pub.size() << "\n";
            return std::nullopt;
        }
        if (blob.size() <= 12) {
            std::cerr << "Ciphertext blob too short (≤ 12 bytes)\n";
            return std::nullopt;
        }

        // Strip the stored nonce prefix — the nonce is re-derived from the
        // key schedule; the transmitted value is not trusted.
        Bytes ct(blob.begin() + 12, blob.end());

        // Replicate the sender's DH computations (X25519 commutativity).
        Bytes dh1(32), dh2(32);
        if (crypto_scalarmult_curve25519(dh1.data(), recipient_priv.data(), ek_pub.data())     != 0 ||
            crypto_scalarmult_curve25519(dh2.data(), recipient_priv.data(), sender_pub.data()) != 0) {
            std::cerr << "DH computation failed\n";
            return std::nullopt;
        }

        // Re-run the identical HKDF key schedule.
        Bytes ikm;
        ikm.insert(ikm.end(), dh1.begin(), dh1.end());
        ikm.insert(ikm.end(), dh2.begin(), dh2.end());
        auto prk = hkdf_extract(ek_pub, ikm);
        auto okm = hkdf_expand(prk, info, 44);

        Bytes aes_key(okm.begin(),      okm.begin() + 32);
        Bytes nonce  (okm.begin() + 32, okm.begin() + 44);

        if (ct.size() < crypto_aead_aes256gcm_ABYTES) {
            std::cerr << "Ciphertext too short for GCM tag\n";
            return std::nullopt;
        }
        Bytes plaintext(ct.size() - crypto_aead_aes256gcm_ABYTES);
        unsigned long long pt_len = 0;
        const auto* ad = aad.empty() ? nullptr
                                     : reinterpret_cast<const unsigned char*>(aad.data());
        const int rc = crypto_aead_aes256gcm_decrypt(
            plaintext.data(), &pt_len,
            nullptr,
            ct.data(), ct.size(),
            ad, aad.size(),
            nonce.data(), aes_key.data());

        sodium_memzero(ikm.data(),     ikm.size());
        sodium_memzero(dh1.data(),     dh1.size());
        sodium_memzero(dh2.data(),     dh2.size());
        sodium_memzero(prk.data(),     prk.size());
        sodium_memzero(okm.data(),     okm.size());
        sodium_memzero(aes_key.data(), aes_key.size());

        if (rc != 0) {
            std::cerr << "AES-256-GCM authentication failed.\n"
                      << "The file was not produced by the expected sender, was\n"
                      << "tampered with, or was relabelled (AAD mismatch).\n";
            return std::nullopt;
        }
        plaintext.resize(pt_len);
        return plaintext;
    } catch (const std::exception& e) {
        std::cerr << "hpke_decapsulate error: " << e.what() << "\n";
        return std::nullopt;
    }
}

} // namespace crypto
