// Secure Mailbox — C++17 CLI client
//
// End-to-end encrypted file mailbox on the /files API.  All cryptography
// lives in Crypto.{hpp,cpp} (HPKE Mode_Auth, matching the Python backend and
// web client); this file is CLI flow only.
//
// Key handling policy (no exceptions):
//   - The private key exists in exactly two places: wrapped inside the
//     passphrase-encrypted vault file (KeyVault), and in process memory
//     after an explicit unlock.  It is never printed, never uploaded, and
//     there is no code path that generates or imports a key without
//     writing a vault.
//   - Peer public keys are TOFU-pinned (PinStore).  A pinned-key mismatch
//     hard-blocks the operation unless the user types an explicit override
//     phrase, which re-pins.

#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <optional>
#include <string>
#include <vector>
#include <sodium.h>
#include "Client.hpp"
#include "Crypto.hpp"
#include "File.hpp"
#include "FileStore.hpp"
#include "KeyVault.hpp"
#include "PinStore.hpp"
#include "User.hpp"

namespace fs = std::filesystem;

// ── CLI helpers ───────────────────────────────────────────────────────────────
namespace cli {

void separator() {
    std::cout << "\n─────────────────────────────────────────\n";
}

void header(const std::string& title) {
    separator();
    std::cout << "  " << title << "\n";
    separator();
}

std::string prompt(const std::string& label) {
    std::cout << label;
    std::string line;
    std::getline(std::cin, line);
    return line;
}

std::string prompt_password(const std::string& label) {
    std::cout << label;
    // stty fails harmlessly on a non-tty (e.g. piped test input).
    if (std::system("stty -echo 2>/dev/null") != 0) { /* not a tty */ }
    std::string pw;
    std::getline(std::cin, pw);
    if (std::system("stty echo 2>/dev/null") != 0)  { /* not a tty */ }
    std::cout << "\n";
    return pw;
}

int menu_choice(const std::string& heading,
                const std::vector<std::string>& options) {
    header(heading);
    for (std::size_t i = 0; i < options.size(); ++i) {
        std::cout << "  [" << (i + 1) << "] " << options[i] << "\n";
    }
    separator();
    while (true) {
        std::string raw = prompt("Choice: ");
        try {
            int choice = std::stoi(raw);
            if (choice >= 1 && choice <= static_cast<int>(options.size()))
                return choice;
        } catch (...) {}
        std::cout << "Invalid choice. Enter 1–" << options.size() << ".\n";
    }
}

std::optional<int> prompt_int(const std::string& label) {
    try {
        return std::stoi(prompt(label));
    } catch (...) {
        std::cout << "Invalid number.\n";
        return std::nullopt;
    }
}

} // namespace cli

// ── Local state locations ─────────────────────────────────────────────────────

// Per-account state directory: $SECUREMAILBOX_HOME or ~/.securemailbox,
// then one subdirectory per username (vault.json + pins.json).
static fs::path account_dir(const std::string& username) {
    if (const char* override_dir = std::getenv("SECUREMAILBOX_HOME")) {
        return fs::path(override_dir) / username;
    }
    const char* home = std::getenv("HOME");
    return fs::path(home ? home : ".") / ".securemailbox" / username;
}

// ── Session state ─────────────────────────────────────────────────────────────

// Client-side upload cap, mirroring the server's ~8 MiB plaintext limit so
// oversize files fail fast locally instead of after a full upload.
constexpr std::int64_t MAX_UPLOAD_BYTES = 8 * 1024 * 1024;

struct Session {
    Client                    client;
    FileStore                 shared_store;   // files shared with me
    FileStore                 owned_store;    // my uploads
    std::optional<crypto::Keypair> keypair;   // set only after a vault unlock
    std::unique_ptr<PinStore> pins;           // constructed after login (per account)

    bool crypto_ready() const { return keypair.has_value(); }
};

// ── TOFU gate ─────────────────────────────────────────────────────────────────

// Fetch `peer`'s public key from the server and verify it against the local
// TOFU pin store.  This is the single chokepoint every encrypt AND decrypt
// path goes through — there is no way to use a peer key without it.
//
// First use: pin and proceed (with a notice).
// Match:     proceed silently.
// Mismatch:  print both fingerprints and refuse unless the user types the
//            exact override phrase; overriding re-pins the new key.
static std::optional<crypto::Bytes> get_verified_peer_key(Session& sess,
                                                          const std::string& peer) {
    auto user_opt = sess.client.get_user(peer);
    if (!user_opt || !user_opt->has_public_key()) {
        std::cout << "User '" << peer << "' not found or has no public key.\n";
        return std::nullopt;
    }
    const std::string& key_b64 = *user_opt->public_key();

    crypto::Bytes key;
    try {
        key = crypto::from_base64(key_b64);
    } catch (...) {
        std::cout << "Failed to decode " << peer << "'s public key.\n";
        return std::nullopt;
    }
    if (key.size() != 32) {
        std::cout << peer << "'s public key is not 32 bytes.\n";
        return std::nullopt;
    }

    const auto result = sess.pins->check(peer, key_b64);
    switch (result.status) {
        case PinStore::Status::Match:
            return key;

        case PinStore::Status::FirstUse:
            sess.pins->pin(peer, key_b64);
            std::cout << "[TOFU] First contact with '" << peer << "' — key pinned.\n"
                      << "       Fingerprint: " << crypto::key_fingerprint(key_b64) << "\n"
                      << "       Verify this out-of-band with them if the file is sensitive.\n";
            return key;

        case PinStore::Status::Mismatch: {
            std::cout << "\n"
                      << "╔══════════════════════════════════════════════════════════════╗\n"
                      << "║  WARNING: " << peer << "'s public key has CHANGED               \n"
                      << "╚══════════════════════════════════════════════════════════════╝\n"
                      << "  Pinned since " << result.pinned_at << ":\n"
                      << "    " << crypto::key_fingerprint(result.pinned_key_b64) << "\n"
                      << "  Key the server returned now:\n"
                      << "    " << crypto::key_fingerprint(key_b64) << "\n\n"
                      << "  Either " << peer << " reset their key (new device / key loss),\n"
                      << "  or the server is substituting a key to intercept this file.\n"
                      << "  Verify the new fingerprint with " << peer << " out-of-band\n"
                      << "  BEFORE trusting it.\n\n";
            const std::string answer =
                cli::prompt("Type exactly 'trust new key' to re-pin, anything else aborts: ");
            if (answer != "trust new key") {
                std::cout << "Aborted — key NOT trusted, operation cancelled.\n";
                return std::nullopt;
            }
            sess.pins->pin(peer, key_b64);
            std::cout << "[TOFU] New key pinned for '" << peer << "'.\n";
            return key;
        }
    }
    return std::nullopt;  // unreachable
}

// ── Vault / key management ────────────────────────────────────────────────────

static bool aes_available_or_warn() {
    if (crypto_aead_aes256gcm_is_available()) return true;
    std::cout << "AES-NI is not available on this CPU — HPKE Mode_Auth requires\n"
              << "hardware AES-256-GCM. Encrypt/decrypt operations are disabled.\n";
    return false;
}

static std::optional<std::string> prompt_new_passphrase() {
    const std::string p1 = cli::prompt_password("Vault passphrase (min 8 chars): ");
    if (p1.size() < 8) {
        std::cout << "Passphrase too short.\n";
        return std::nullopt;
    }
    const std::string p2 = cli::prompt_password("Repeat passphrase           : ");
    if (p1 != p2) {
        std::cout << "Passphrases do not match.\n";
        return std::nullopt;
    }
    return p1;
}

// Create a vault around `kp`, upload the public key, and load it into the
// session.  This is the ONLY way key material enters a session apart from
// unlocking an existing vault — generation/import without a vault is not
// offered anywhere.
static bool finalize_new_key(Session& sess, const KeyVault& vault, crypto::Keypair kp) {
    const auto passphrase = prompt_new_passphrase();
    if (!passphrase) return false;

    std::cout << "Deriving vault key (Argon2id, 256 MiB — takes a moment)…\n";
    if (!vault.create(kp, *passphrase)) {
        std::cout << "Vault creation failed — key discarded.\n";
        sodium_memzero(kp.priv.data(), kp.priv.size());
        return false;
    }
    std::cout << "Vault written to " << vault.path() << "\n";

    const std::string pub_b64 = crypto::to_base64(kp.pub);
    std::cout << "Uploading public key to server…\n";
    if (!sess.client.upload_public_key(pub_b64)) {
        std::cout << "Public key upload failed — you can retry from the key menu.\n";
    }
    std::cout << "Your key fingerprint (share out-of-band so peers can verify you):\n"
              << "  " << crypto::key_fingerprint(pub_b64) << "\n";

    sess.keypair = std::move(kp);
    return true;
}

static bool unlock_vault(Session& sess, const KeyVault& vault) {
    for (int attempt = 1; attempt <= 3; ++attempt) {
        const std::string passphrase =
            cli::prompt_password("Vault passphrase: ");
        std::cout << "Unlocking (Argon2id)…\n";
        auto kp = vault.unlock(passphrase);
        if (kp) {
            sess.keypair = std::move(*kp);
            std::cout << "Vault unlocked.\n";

            // Cross-check the vault's public key against the server record.
            // A mismatch means the server has a different (older or foreign)
            // key for us — files encrypted to it are not ours to decrypt.
            auto me = sess.client.get_user(sess.client.logged_in_as());
            const std::string vault_pub = crypto::to_base64(sess.keypair->pub);
            if (me && me->has_public_key() && *me->public_key() != vault_pub) {
                std::cout << "\nNOTE: the server has a DIFFERENT public key on record for\n"
                          << "your account than this vault holds.\n";
                if (cli::prompt("Re-upload this vault's public key? [y/N]: ") == "y") {
                    sess.client.upload_public_key(vault_pub);
                }
            }
            return true;
        }
        std::cout << "Wrong passphrase (or corrupt vault). "
                  << (3 - attempt) << " attempt(s) left.\n";
    }
    return false;
}

// Post-login key setup.  Every path through here either ends with an
// unlocked vault or with NO key in the session — there is no in-memory-only
// keypair state.
static void setup_keys(Session& sess) {
    const KeyVault vault(account_dir(sess.client.logged_in_as()) / "vault.json");

    if (vault.exists()) {
        if (!unlock_vault(sess, vault)) {
            std::cout << "Vault locked — encrypt/decrypt unavailable this session.\n";
        }
        return;
    }

    cli::header("No key vault found for this account on this machine");
    const int choice = cli::menu_choice("Key setup", {
        "Generate a new keypair (writes a passphrase-encrypted vault)",
        "Import an existing private key (writes a passphrase-encrypted vault)",
        "Skip — browse only, no encrypt/decrypt this session",
    });

    if (choice == 1) {
        finalize_new_key(sess, vault, crypto::generate_keypair());
    } else if (choice == 2) {
        // Import path for users migrating a key from another machine.  The
        // key is immediately wrapped into a vault — it is not usable
        // in-session without one.
        const std::string priv_b64 = cli::prompt_password("Private key (base64, hidden): ");
        try {
            crypto::Keypair kp;
            kp.priv = crypto::from_base64(priv_b64);
            if (kp.priv.size() != 32) {
                std::cout << "Private key must decode to exactly 32 bytes.\n";
                return;
            }
            // Recompute the public key from the scalar rather than asking for
            // it — eliminates mismatched-pair mistakes.
            kp.pub.resize(32);
            crypto_scalarmult_curve25519_base(kp.pub.data(), kp.priv.data());
            finalize_new_key(sess, vault, std::move(kp));
        } catch (const std::exception& e) {
            std::cout << "Import failed: " << e.what() << "\n";
        }
    }
    // choice 3: fall through with no keypair — crypto verbs will refuse.
}

// ── File listings ─────────────────────────────────────────────────────────────

static void print_file_row(const File& f, bool owned_view) {
    const std::string name = f.filename() ? *f.filename()
                           : f.subject()  ? *f.subject() : "(unnamed)";
    std::cout << "[" << (f.is_read() ? " " : "*") << "] #" << f.id() << "  " << name;
    if (owned_view) {
        if (f.recipient_username()) std::cout << "  → " << *f.recipient_username();
    } else {
        if (f.owner_username())     std::cout << "  from " << *f.owner_username();
    }
    if (f.size_bytes()) std::cout << "  (" << *f.size_bytes() << " bytes)";
    if (f.is_forwarded().value_or(false)) std::cout << "  [shared copy]";
    std::cout << "  " << f.created_at() << "\n";
}

static void do_list_shared(Session& sess) {
    cli::header("Files shared with me");
    auto files = sess.client.get_shared();
    if (files.empty()) { std::cout << "  (none)\n"; return; }
    sess.shared_store.replace_all(std::move(files));
    for (const auto& f : sess.shared_store.sorted_by_date_desc()) {
        print_file_row(f, /*owned_view=*/false);
    }
}

static void do_list_owned(Session& sess) {
    cli::header("My uploads");
    auto files = sess.client.get_owned();
    if (files.empty()) { std::cout << "  (none)\n"; return; }
    sess.owned_store.replace_all(std::move(files));
    for (const auto& f : sess.owned_store.sorted_by_date_desc()) {
        print_file_row(f, /*owned_view=*/true);
    }
}

// ── Upload ────────────────────────────────────────────────────────────────────

static std::optional<crypto::Bytes> read_local_file(const fs::path& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        std::cout << "Cannot open " << path << "\n";
        return std::nullopt;
    }
    crypto::Bytes data((std::istreambuf_iterator<char>(in)),
                        std::istreambuf_iterator<char>());
    return data;
}

static void do_upload(Session& sess) {
    cli::header("Encrypt & upload a file (HPKE Mode_Auth)");

    if (!sess.crypto_ready()) {
        std::cout << "No unlocked vault — set up or unlock your key first (key menu).\n";
        return;
    }
    if (!aes_available_or_warn()) return;

    const fs::path path = cli::prompt("Local file path: ");
    std::error_code ec;
    const auto fsize = fs::file_size(path, ec);
    if (ec) { std::cout << "Cannot stat " << path << "\n"; return; }
    if (static_cast<std::int64_t>(fsize) > MAX_UPLOAD_BYTES) {
        std::cout << "File is " << fsize << " bytes — the upload cap is "
                  << MAX_UPLOAD_BYTES << " (~8 MiB).\n";
        return;
    }

    const std::string recipient = cli::prompt("Recipient username: ");
    auto recipient_key = get_verified_peer_key(sess, recipient);
    if (!recipient_key) return;

    auto plaintext = read_local_file(path);
    if (!plaintext) return;

    const std::string filename = path.filename().string();
    const std::string aad = crypto::build_file_aad(
        sess.client.logged_in_as(), recipient, filename);

    std::cout << "Encrypting " << plaintext->size() << " bytes…\n";
    crypto::EncryptedFile enc;
    try {
        enc = crypto::hpke_encapsulate(*plaintext, *recipient_key,
                                       sess.keypair->priv, aad);
    } catch (const std::exception& e) {
        std::cout << "Encryption error: " << e.what() << "\n";
        return;
    }

    UploadPayload payload;
    payload.ciphertext_b64    = std::move(enc.ciphertext_b64);
    payload.nonce_b64         = std::move(enc.nonce_b64);
    payload.encrypted_key_b64 = std::move(enc.encrypted_key_b64);
    payload.associated_data   = aad;
    payload.filename          = filename;
    payload.content_type      = "application/octet-stream";
    payload.size_bytes        = static_cast<std::int64_t>(plaintext->size());

    auto id = sess.client.upload_file(recipient, payload);
    if (id) {
        std::cout << "Uploaded as file #" << *id << " for " << recipient << ".\n";
    }
}

// ── Download ──────────────────────────────────────────────────────────────────

// Download + TOFU-verify + decrypt a file.  Returns the plaintext and the
// download metadata so `share` can reuse this path.
static std::optional<std::pair<crypto::Bytes, File>>
fetch_and_decrypt(Session& sess, int file_id) {
    if (!sess.crypto_ready()) {
        std::cout << "No unlocked vault — set up or unlock your key first (key menu).\n";
        return std::nullopt;
    }
    if (!aes_available_or_warn()) return std::nullopt;

    auto file_opt = sess.client.download_file(file_id);
    if (!file_opt) {
        std::cout << "File not found or access denied.\n";
        return std::nullopt;
    }
    File file = std::move(*file_opt);

    if (!file.owner_username()) {
        std::cout << "Uploader unknown — cannot verify sender key.\n";
        return std::nullopt;
    }
    const std::string& owner = *file.owner_username();

    if (owner == sess.client.logged_in_as()) {
        std::cout << "This is your own upload. The content key is derived from the\n"
                  << "RECIPIENT's key pair (HPKE property) — the uploader cannot\n"
                  << "decrypt it. Keep your local copy of the original file.\n";
        return std::nullopt;
    }
    if (!file.ciphertext() || !file.encrypted_key()) {
        std::cout << "Missing ciphertext or encrypted_key — cannot decrypt.\n";
        return std::nullopt;
    }

    // TOFU gate on the sender's key — a substituted key fails here, before
    // any cryptography runs.
    auto owner_key = get_verified_peer_key(sess, owner);
    if (!owner_key) return std::nullopt;

    // Rebuild the canonical AAD LOCALLY from download metadata + our own
    // username.  The server's associated_data string is deliberately ignored:
    // trusting it would let a malicious server strip the relabelling
    // protection.  There is no AAD-less retry for the same reason.
    const std::string aad = crypto::build_file_aad(
        owner, sess.client.logged_in_as(),
        file.filename().value_or(""));

    std::cout << "Decapsulating (HPKE Mode_Auth)…\n";
    auto plaintext = crypto::hpke_decapsulate(
        *file.ciphertext(), *file.encrypted_key(),
        sess.keypair->priv, *owner_key, aad);

    if (!plaintext) {
        std::cout << "Decryption failed. Possible causes:\n"
                  << "  • The file metadata (e.g. filename) was altered after upload\n"
                  << "    — the AAD binding rejects relabelled files\n"
                  << "  • The uploader's key rotated since encryption\n"
                  << "  • Ciphertext tampering, or a pre-AAD legacy upload\n";
        return std::nullopt;
    }
    return std::make_pair(std::move(*plaintext), std::move(file));
}

static void do_download(Session& sess) {
    cli::header("Download & decrypt a file");
    const auto id = cli::prompt_int("File ID: ");
    if (!id) return;

    auto result = fetch_and_decrypt(sess, *id);
    if (!result) return;
    auto& [plaintext, file] = *result;

    const std::string default_name = file.filename().value_or(
        "file_" + std::to_string(file.id()) + ".bin");
    std::string out_str = cli::prompt("Save as [" + default_name + "]: ");
    if (out_str.empty()) out_str = default_name;

    const fs::path out_path = out_str;
    if (fs::exists(out_path) &&
        cli::prompt("File exists — overwrite? [y/N]: ") != "y") {
        std::cout << "Aborted.\n";
        return;
    }
    std::ofstream out(out_path, std::ios::binary | std::ios::trunc);
    if (!out) { std::cout << "Cannot write " << out_path << "\n"; return; }
    out.write(reinterpret_cast<const char*>(plaintext.data()),
              static_cast<std::streamsize>(plaintext.size()));
    out.close();
    std::cout << "Decrypted " << plaintext.size() << " bytes → " << out_path << "\n";
}

// ── Share / revoke / delete ───────────────────────────────────────────────────

static void do_share(Session& sess) {
    cli::header("Share a file (decrypt + re-encrypt for a new recipient)");
    std::cout << "Sharing works on files SHARED WITH YOU: the content key of an\n"
              << "HPKE ciphertext is derived from the recipient's key pair, so\n"
              << "only a recipient can decrypt and re-encrypt it onward.\n\n";

    const auto id = cli::prompt_int("File ID to share: ");
    if (!id) return;

    auto result = fetch_and_decrypt(sess, *id);
    if (!result) return;
    auto& [plaintext, file] = *result;

    const std::string new_recipient = cli::prompt("Share with (username): ");
    if (new_recipient == sess.client.logged_in_as()) {
        std::cout << "That's you.\n";
        return;
    }
    auto recipient_key = get_verified_peer_key(sess, new_recipient);
    if (!recipient_key) return;

    // Fresh encapsulation with a new AAD naming US as the sender — the
    // re-encrypted copy is a new file authored by the sharer.
    const std::string aad = crypto::build_file_aad(
        sess.client.logged_in_as(), new_recipient,
        file.filename().value_or(""));

    std::cout << "Re-encrypting for " << new_recipient << "…\n";
    crypto::EncryptedFile enc;
    try {
        enc = crypto::hpke_encapsulate(plaintext, *recipient_key,
                                       sess.keypair->priv, aad);
    } catch (const std::exception& e) {
        std::cout << "Encryption error: " << e.what() << "\n";
        return;
    }

    if (sess.client.share_file(*id, new_recipient,
                               enc.ciphertext_b64, enc.nonce_b64,
                               enc.encrypted_key_b64)) {
        std::cout << "Shared with " << new_recipient << ".\n";
    }
}

static void do_revoke(Session& sess) {
    cli::header("Revoke access (owner only)");
    const auto id = cli::prompt_int("File ID: ");
    if (!id) return;
    const std::string who =
        cli::prompt("Recipient to revoke (Enter = revoke ALL recipients): ");
    const std::optional<std::string> target =
        who.empty() ? std::nullopt : std::optional<std::string>{who};
    if (sess.client.revoke_access(*id, target)) {
        std::cout << (target ? "Access revoked for " + *target
                             : std::string("All access revoked")) << ".\n";
    }
}

static void do_delete(Session& sess) {
    cli::header("Delete a file (owner only, soft delete)");
    const auto id = cli::prompt_int("File ID to delete: ");
    if (!id) return;
    if (sess.client.delete_file(*id))
        std::cout << "File #" << *id << " deleted.\n";
}

static void do_lookup_user(Session& sess) {
    cli::header("Look up user");
    const std::string username = cli::prompt("Username: ");
    auto user_opt = sess.client.get_user(username);
    if (!user_opt) { std::cout << "User not found or inactive.\n"; return; }
    std::cout << "  id         : " << user_opt->id()
              << "\n  username   : " << user_opt->username() << "\n";
    if (user_opt->has_public_key()) {
        std::cout << "  fingerprint: "
                  << crypto::key_fingerprint(*user_opt->public_key()) << "\n";
        const auto pin = sess.pins->check(username, *user_opt->public_key());
        std::cout << "  TOFU pin   : "
                  << (pin.status == PinStore::Status::Match    ? "matches pinned key" :
                      pin.status == PinStore::Status::Mismatch ? "MISMATCH vs pinned key!"
                                                               : "not pinned yet")
                  << "\n";
    } else {
        std::cout << "  public key : (none uploaded)\n";
    }
}

static void do_unread_summary(Session& sess) {
    const auto unread = sess.shared_store.unread();
    if (!unread.empty())
        std::cout << "\n  [!] " << unread.size() << " unread shared file(s)\n";
}

// ── Auth flows ────────────────────────────────────────────────────────────────

static void do_register(Session& sess) {
    cli::header("Register new account");
    const std::string username = cli::prompt("Username : ");
    const std::string email    = cli::prompt("Email    : ");
    const std::string password = cli::prompt_password("Password : ");
    if (sess.client.register_user(username, email, password)) {
        std::cout << "Account created. Log in to set up your key vault.\n";
    }
}

static bool do_login(Session& sess) {
    cli::header("Login");
    const std::string username = cli::prompt("Username : ");
    const std::string password = cli::prompt_password("Password : ");
    if (!sess.client.login(username, password)) return false;
    std::cout << "Logged in as " << username << ".\n";

    // Per-account TOFU pin store — must exist before any key fetch.
    sess.pins = std::make_unique<PinStore>(account_dir(username) / "pins.json");

    setup_keys(sess);
    return true;
}

// ── Main menu loop ────────────────────────────────────────────────────────────

static void run_logged_in(Session& sess) {
    const std::string heading = "Logged in as: " + sess.client.logged_in_as() +
        (sess.crypto_ready() ? "  [vault unlocked]" : "  [NO KEY — browse only]");
    while (true) {
        do_unread_summary(sess);
        const int choice = cli::menu_choice(heading, {
            "List files shared with me",
            "List my uploads",
            "Encrypt & upload a file",
            "Download & decrypt a file",
            "Share a file",
            "Revoke access to a file",
            "Delete a file",
            "Look up a user",
            "Key vault setup / unlock",
            "Logout",
            "Exit",
        });
        switch (choice) {
            case 1:  do_list_shared(sess); break;
            case 2:  do_list_owned(sess);  break;
            case 3:  do_upload(sess);      break;
            case 4:  do_download(sess);    break;
            case 5:  do_share(sess);       break;
            case 6:  do_revoke(sess);      break;
            case 7:  do_delete(sess);      break;
            case 8:  do_lookup_user(sess); break;
            case 9:
                if (sess.crypto_ready())
                    std::cout << "Vault already unlocked this session.\n";
                else
                    setup_keys(sess);
                break;
            case 10:
                sess.client.logout();
                if (sess.keypair)
                    sodium_memzero(sess.keypair->priv.data(), sess.keypair->priv.size());
                sess.keypair.reset();
                sess.pins.reset();
                sess.shared_store.clear();
                sess.owned_store.clear();
                std::cout << "Logged out.\n";
                return;
            case 11:
                sess.client.logout();
                if (sess.keypair)
                    sodium_memzero(sess.keypair->priv.data(), sess.keypair->priv.size());
                std::exit(0);
        }
    }
}

// ── Entry point ───────────────────────────────────────────────────────────────

int main(int argc, char* argv[]) {
    if (sodium_init() < 0) {
        std::cerr << "Failed to initialise libsodium.\n";
        return 1;
    }

    ClientConfig cfg;
    if (argc >= 2) cfg.base_url = argv[1];

    std::cout << "=== Secure Mailbox CLI (HPKE Mode_Auth) ===\n"
              << "Server: " << cfg.base_url << "\n";

    if (!crypto_aead_aes256gcm_is_available()) {
        std::cout << "\nNOTE: AES-NI not available on this CPU.\n"
                  << "libsodium's AES-256-GCM requires hardware acceleration;\n"
                  << "upload and download/decrypt will be disabled.\n"
                  << "(The key vault itself uses XSalsa20-Poly1305 and still works.)\n\n";
    }

    Session sess{Client{cfg}, {}, {}, std::nullopt, nullptr};

    while (true) {
        const int choice = cli::menu_choice("Main Menu", {
            "Login",
            "Register new account",
            "Exit",
        });
        switch (choice) {
            case 1:
                if (do_login(sess)) run_logged_in(sess);
                break;
            case 2:
                do_register(sess);
                break;
            case 3:
                return 0;
        }
    }
}
