#pragma once
#include <memory>
#include <optional>
#include <string>
#include <vector>
#include <curl/curl.h>
#include "Message.hpp"
#include "User.hpp"

struct ClientConfig {
    std::string base_url{"http://localhost:8000"};
    // Set false for local dev servers that have no TLS certificate.
    bool verify_ssl{false};
};

// HTTP client for the Secure Messenger backend API.
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
    // Sends form-encoded credentials (OAuth2PasswordRequestForm).
    // Stores access_token and refresh_token on success.
    bool login(const std::string& username, const std::string& password);
    // POST /auth/logout — requires a prior successful login().
    bool logout();
    // POST /auth/register — JSON body; does not log in automatically.
    bool register_user(const std::string& username,
                       const std::string& email,
                       const std::string& password);

    bool        is_logged_in()  const noexcept { return !access_token_.empty(); }
    const std::string& logged_in_as() const noexcept { return username_; }

    // ── Key discovery (no auth required) ─────────────────────────────────────
    std::optional<User> get_user(const std::string& username);
    std::vector<User>   list_users(int skip = 0, int limit = 100);

    // POST /users/keys — JWT required; uploads caller's X25519 public key.
    bool upload_public_key(const std::string& public_key_b64);

    // ── Messages ──────────────────────────────────────────────────────────────
    // POST /messages/send — ciphertext_b64 and nonce_b64 must already be
    // encrypted by the caller; the server stores them opaquely.
    bool send_message(const std::string& recipient_username,
                      const std::string& ciphertext_b64,
                      const std::string& nonce_b64,
                      const std::optional<std::string>& subject          = std::nullopt,
                      const std::optional<std::string>& encrypted_key_b64 = std::nullopt);

    std::vector<Message>  get_inbox(int skip = 0, int limit = 50);
    std::vector<Message>  get_sent (int skip = 0, int limit = 50);
    std::optional<Message> download_message(int message_id);
    bool                   delete_message  (int message_id);

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
