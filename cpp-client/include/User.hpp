#pragma once
#include <optional>
#include <string>

// Immutable value type representing a remote user as returned by the
// key-discovery endpoints (GET /users, GET /users/{username}).
// Only the fields the server exposes publicly are stored — email is absent
// because those endpoints are unauthenticated and should not expose PII.
class User {
public:
    User() = default;
    User(int id, std::string username, std::optional<std::string> public_key);

    int                             id()         const noexcept { return id_; }
    const std::string&              username()   const noexcept { return username_; }
    // Base64-encoded 32-byte X25519 public key, or nullopt if not yet uploaded.
    const std::optional<std::string>& public_key() const noexcept { return public_key_; }
    bool has_public_key()           const noexcept { return public_key_.has_value(); }

private:
    int                          id_{0};
    std::string                  username_;
    std::optional<std::string>   public_key_;
};
