#pragma once
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>
#include <curl/curl.h>
#include "File.hpp"
#include "User.hpp"

struct ClientConfig {
    std::string base_url{"https://team10.theburkenator.com"};
    // Set false for local dev servers that have no TLS certificate.
    bool verify_ssl{true};
};

// Everything needed for POST /files/upload except the recipient — the
// ciphertext fields come from crypto::hpke_encapsulate(), the metadata from
// the local file being uploaded.
struct UploadPayload {
    std::string                ciphertext_b64;
    std::string                nonce_b64;
    std::string                encrypted_key_b64;
    std::string                associated_data;   // canonical AAD string (bound in the AEAD)
    std::optional<std::string> filename;
    std::optional<std::string> content_type;
    std::optional<std::int64_t> size_bytes;       // plaintext size
    std::optional<std::string> subject;
};

// HTTP client for the Secure Mailbox backend API.
//
// Manages a single libcurl handle via RAII (CurlHandle unique_ptr).
// All public methods are synchronous; they block until the server responds.
// Thread safety: NOT thread-safe — use one Client per thread.
class Client {
public:
    explicit Client(ClientConfig config = {});

    // Destructor, move: handled automatically by CurlHandle (unique_ptr).
    ~Client() = default;
    Client(const Client&)            = delete;
    Client& operator=(const Client&) = delete;
    Client(Client&&)                 = default;
    Client& operator=(Client&&)      = default;

    // ── Authentication ────────────────────────────────────────────────────────
    // Stores access_token and refresh_token on success.
    bool login(const std::string& username, const std::string& password);
    // POST /auth/logout — requires a prior successful login().
    bool logout();
    // POST /auth/register — JSON body; does not log in automatically.
    bool register_user(const std::string& username,
                       const std::string& email,
                       const std::string& password);

    bool               is_logged_in()  const noexcept { return !access_token_.empty(); }
    const std::string& logged_in_as() const noexcept { return username_; }

    // ── Key discovery (no auth required) ─────────────────────────────────────
    std::optional<User> get_user(const std::string& username);
    std::vector<User>   list_users(int skip = 0, int limit = 100);

    // POST /users/keys — JWT required; uploads caller's X25519 public key.
    bool upload_public_key(const std::string& public_key_b64);

    // ── Files ─────────────────────────────────────────────────────────────────
    // POST /files/upload — payload fields must already be encrypted by the
    // caller; the server stores them opaquely.  Returns the new file's id.
    std::optional<int> upload_file(const std::string& recipient_username,
                                   const UploadPayload& payload);

    std::vector<File>   get_shared(int skip = 0, int limit = 50);  // shared with me
    std::vector<File>   get_owned (int skip = 0, int limit = 50);  // my uploads
    std::optional<File> download_file(int file_id);
    bool                delete_file  (int file_id);                // owner-only soft delete

    // On-chain MessageReceipt status for a file, read via
    // GET /files/{id}/blockchain-proof. Informational (fail-open) — used to
    // report whether the server posted a receipt after an accepted upload.
    struct ReceiptStatus {
        bool        queried{false};   // false → the request itself failed
        bool        confirmed{false}; // receipt exists on-chain
        std::string tx_hash;          // posting tx, if the server recorded one
        std::int64_t block_number{0}; // block the receipt landed in (when confirmed)
    };
    ReceiptStatus get_receipt_status(int file_id);

    // POST /files/{id}/share — re-encryption path: the sharer decrypted the
    // file locally and re-encrypted it for the new recipient.
    bool share_file(int file_id,
                    const std::string& recipient_username,
                    const std::string& new_ciphertext_b64,
                    const std::string& new_nonce_b64,
                    const std::string& new_encrypted_key_b64);

    // POST /files/{id}/revoke — owner-only.  With a username: targeted
    // revocation; without: removes every recipient's access.
    bool revoke_access(int file_id,
                       const std::optional<std::string>& recipient_username = std::nullopt);

private:
    // RAII handle: curl_easy_cleanup is called automatically when the
    // unique_ptr is destroyed or reset.
    struct CurlDeleter {
        void operator()(CURL* c) const noexcept { curl_easy_cleanup(c); }
    };
    using CurlHandle = std::unique_ptr<CURL, CurlDeleter>;

    struct HttpResponse {
        long        status_code{0};
        std::string body;
    };

    // Generic request helper.  form_encoded=true sends body as
    // application/x-www-form-urlencoded instead of application/json.
    HttpResponse request(const std::string& method,
                         const std::string& path,
                         const std::string& body        = "",
                         bool               form_encoded = false);

    // Fetch a paginated file listing (shared/owned) and parse it.
    std::vector<File> get_file_listing(const std::string& endpoint, int skip, int limit);

    // Percent-encode a string for safe embedding in a URL path or query string.
    std::string url_encode(const std::string& value) const;

    // libcurl write callback: appends received bytes to a std::string.
    static size_t write_callback(char* ptr, size_t size, size_t nmemb, void* userdata);

    ClientConfig config_;
    CurlHandle   curl_;
    std::string  access_token_;
    std::string  refresh_token_;
    std::string  username_;
};
