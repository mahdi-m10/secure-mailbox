#pragma once
#include <optional>
#include <string>

// Value type for a single message.
//
// Inbox and sent-list endpoints return summary items — the ciphertext,
// nonce, associated_data and encrypted_key fields are absent until the
// caller explicitly fetches GET /messages/{id}/download.
class Message {
public:
    Message() = default;

    // Constructor used when parsing inbox / sent listings.
    Message(int                        id,
            std::optional<int>         sender_id,
            std::optional<std::string> sender_username,
            std::optional<std::string> subject,
            bool                       is_read,
            bool                       is_deleted,
            std::string                created_at);

    // ── Listing fields (always populated) ────────────────────────────────────
    int                               id()             const noexcept { return id_; }
    std::optional<int>                sender_id()      const noexcept { return sender_id_; }
    const std::optional<std::string>& sender_username()const noexcept { return sender_username_; }
    const std::optional<std::string>& subject()        const noexcept { return subject_; }
    bool                              is_read()        const noexcept { return is_read_; }
    bool                              is_deleted()     const noexcept { return is_deleted_; }
    const std::string&                created_at()     const noexcept { return created_at_; }

    // ── Download-only fields (optional until downloaded) ─────────────────────
    // base64(nonce_12 ‖ ciphertext_with_tag) — the combined blob stored server-side
    const std::optional<std::string>& ciphertext()      const noexcept { return ciphertext_; }
    // nonce extracted from the first 12 decoded bytes of ciphertext, base64-re-encoded
    const std::optional<std::string>& nonce()           const noexcept { return nonce_; }
    // canonical AAD: "v1:sender={id}:recipient={id}:msg={id}" — pass to decrypt()
    const std::optional<std::string>& associated_data() const noexcept { return associated_data_; }
    // the recipient's wrapped symmetric key; decrypt with your private key first
    const std::optional<std::string>& encrypted_key()   const noexcept { return encrypted_key_; }
    const std::optional<std::string>& integrity_hash()  const noexcept { return integrity_hash_; }

    // Setters called by Client::download_message() after a successful download
    void set_ciphertext(std::string v)      { ciphertext_      = std::move(v); }
    void set_nonce(std::string v)           { nonce_           = std::move(v); }
    void set_associated_data(std::string v) { associated_data_ = std::move(v); }
    void set_encrypted_key(std::string v)   { encrypted_key_   = std::move(v); }
    void set_integrity_hash(std::string v)  { integrity_hash_  = std::move(v); }
    void mark_read() noexcept               { is_read_ = true; }

private:
    int                        id_{0};
    std::optional<int>         sender_id_;
    std::optional<std::string> sender_username_;
    std::optional<std::string> subject_;
    bool                       is_read_{false};
    bool                       is_deleted_{false};
    std::string                created_at_;

    // Populated only after GET /messages/{id}/download
    std::optional<std::string> ciphertext_;
    std::optional<std::string> nonce_;
    std::optional<std::string> associated_data_;
    std::optional<std::string> encrypted_key_;
    std::optional<std::string> integrity_hash_;
};
