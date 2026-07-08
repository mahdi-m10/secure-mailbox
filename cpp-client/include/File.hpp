#pragma once
#include <cstdint>
#include <optional>
#include <string>

// Value type for a single file record as returned by the /files API.
//
// Listing endpoints (GET /files/shared, GET /files/owned) return summary
// items — ciphertext, nonce, associated_data and encrypted_key are absent
// until the caller explicitly fetches GET /files/{id}/download.
class File {
public:
    // Listing fields, grouped in an aggregate so the JSON parser can use
    // designated-style member assignment instead of a 12-argument constructor.
    struct Fields {
        int                          id{0};
        std::optional<int>           owner_id;
        std::optional<std::string>   owner_username;
        std::optional<std::string>   recipient_username;  // owned listings only
        std::optional<std::string>   subject;
        std::optional<std::string>   filename;
        std::optional<std::string>   content_type;
        std::optional<std::int64_t>  size_bytes;
        bool                         is_read{false};
        bool                         is_deleted{false};
        std::optional<bool>          is_forwarded;        // true for share-created rows
        std::string                  created_at;          // ISO-8601
    };

    File() = default;
    explicit File(Fields f) : f_(std::move(f)) {}

    // ── Listing fields (always populated) ────────────────────────────────────
    int                                id()                 const noexcept { return f_.id; }
    std::optional<int>                 owner_id()           const noexcept { return f_.owner_id; }
    const std::optional<std::string>&  owner_username()     const noexcept { return f_.owner_username; }
    const std::optional<std::string>&  recipient_username() const noexcept { return f_.recipient_username; }
    const std::optional<std::string>&  subject()            const noexcept { return f_.subject; }
    const std::optional<std::string>&  filename()           const noexcept { return f_.filename; }
    const std::optional<std::string>&  content_type()       const noexcept { return f_.content_type; }
    std::optional<std::int64_t>        size_bytes()         const noexcept { return f_.size_bytes; }
    bool                               is_read()            const noexcept { return f_.is_read; }
    bool                               is_deleted()         const noexcept { return f_.is_deleted; }
    std::optional<bool>                is_forwarded()       const noexcept { return f_.is_forwarded; }
    const std::string&                 created_at()         const noexcept { return f_.created_at; }

    // ── Download-only fields (populated after GET /files/{id}/download) ──────
    // base64(nonce_12 ‖ ciphertext_with_tag) — the combined blob stored server-side
    const std::optional<std::string>& ciphertext()      const noexcept { return ciphertext_; }
    // nonce extracted from the first 12 decoded bytes, base64-re-encoded (informational)
    const std::optional<std::string>& nonce()           const noexcept { return nonce_; }
    // The server's canonical AAD string.  INFORMATIONAL ONLY — decryption must
    // rebuild the AAD locally with crypto::build_file_aad(); trusting this
    // string would let a malicious server defeat the relabelling protection.
    const std::optional<std::string>& associated_data() const noexcept { return associated_data_; }
    // base64(32-byte ephemeral public key ek_pub) — HPKE encapsulated key
    const std::optional<std::string>& encrypted_key()   const noexcept { return encrypted_key_; }
    const std::optional<std::string>& integrity_hash()  const noexcept { return integrity_hash_; }

    // Setters called by Client::download_file() after a successful download
    void set_ciphertext(std::string v)      { ciphertext_      = std::move(v); }
    void set_nonce(std::string v)           { nonce_           = std::move(v); }
    void set_associated_data(std::string v) { associated_data_ = std::move(v); }
    void set_encrypted_key(std::string v)   { encrypted_key_   = std::move(v); }
    void set_integrity_hash(std::string v)  { integrity_hash_  = std::move(v); }
    void mark_read() noexcept               { f_.is_read = true; }

private:
    Fields f_;

    // Populated only after GET /files/{id}/download
    std::optional<std::string> ciphertext_;
    std::optional<std::string> nonce_;
    std::optional<std::string> associated_data_;
    std::optional<std::string> encrypted_key_;
    std::optional<std::string> integrity_hash_;
};
