#pragma once
#include <filesystem>
#include <map>
#include <string>

// PinStore — trust-on-first-use (TOFU) public-key pinning.
//
// Same trust model as the web client's IndexedDB pin store: the first time a
// peer's public key is fetched it is pinned; every later fetch is compared
// against the pin.  A mismatch means either the peer legitimately rotated
// their key or the server (compromised or malicious) substituted a key to
// mount a man-in-the-middle — the client cannot tell which, so it must
// hard-stop and put the decision in the user's hands.
//
// Pins live in a per-account JSON file (mode 0600):
//   { "peer_username": { "public_key": "<b64>", "pinned_at": "<ISO-8601>" }, … }
//
// Keying the file per local account keeps trust stores independent when
// multiple accounts are used on one machine (mirrors the web client's
// `${myUsername}|${peerUsername}` composite key).
class PinStore {
public:
    enum class Status { FirstUse, Match, Mismatch };

    struct CheckResult {
        Status      status;
        std::string pinned_key_b64;  // set for Match / Mismatch
        std::string pinned_at;       // set for Match / Mismatch
    };

    // Loads existing pins from `path` if present.
    explicit PinStore(std::filesystem::path path);

    // Compare `key_b64` against the stored pin for `peer`.  Read-only —
    // first-use pinning is an explicit pin() call so the caller controls
    // when trust is actually recorded.
    CheckResult check(const std::string& peer, const std::string& key_b64) const;

    // Record (or replace, after an explicit user override) the pin for
    // `peer` and persist the file immediately.
    void pin(const std::string& peer, const std::string& key_b64);

    std::size_t size() const noexcept { return pins_.size(); }

private:
    struct Entry {
        std::string public_key_b64;
        std::string pinned_at;
    };

    void load();
    void save() const;

    std::filesystem::path        path_;
    std::map<std::string, Entry> pins_;  // peer username → pin
};
