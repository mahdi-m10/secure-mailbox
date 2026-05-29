// Secure Messenger — C++17 CLI client
//
// Cryptography scheme: HPKE Mode_Auth (RFC 9180) — matches backend/crypto/hpke.py
//
//   Key generation
//       crypto_box_keypair() → 32-byte Curve25519/X25519 (Montgomery form).
//       Wire-compatible with Python's X25519PrivateKey / X25519PublicKey from
//       the cryptography library.  Upload the public key via POST /users/keys.
//
//   Encapsulation (encrypt_for → hpke_encapsulate)
//       Mirrors the Python encapsulate() function exactly:
//       1. Fresh ephemeral X25519 keypair (ek_priv discarded after use).
//       2. dh1 = X25519(ek_priv,     recip_pub)   — standard DH
//          dh2 = X25519(sender_priv, recip_pub)   — Mode_Auth authentication
//       3. HKDF-SHA256(ikm=dh1‖dh2, salt=ek_pub, info, length=44)
//          → aes_key (bytes 0–31) + nonce (bytes 32–43)
//       4. AES-256-GCM(aes_key, nonce, plaintext) — requires AES-NI hardware
//       5. encrypted_key field = ek_pub (32 bytes), NOT a wrapped message key.
//
//   Decapsulation (decrypt → hpke_decapsulate)
//       Mirrors Python decapsulate():
//       Re-runs the DH + HKDF key schedule from (recip_priv, sender_pub, ek_pub),
//       re-derives the nonce, decrypts the GCM ciphertext.
//       Decryption succeeds iff the message was produced by whoever holds
//       sender_priv — the GCM tag provides implicit sender authentication.
//
//   HKDF-SHA256 (RFC 5869) is built from libsodium's crypto_auth_hmacsha256
//   because libsodium 1.0.18 (Ubuntu 20.04/22.04) does not ship the
//   crypto_kdf_hkdf_sha256_* helpers introduced in 1.0.19.
//
//   AES-256-GCM requires hardware acceleration.  Call sodium_init() first,
//   then check crypto_aead_aes256gcm_is_available() before encapsulating.
//
//   Private keys are held in memory only — save them yourself before exiting.

#include <algorithm>
#include <iostream>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>
#include <sodium.h>
#include "Client.hpp"
#include "Message.hpp"
#include "MessageStore.hpp"
#include "User.hpp"

// ── crypto namespace ──────────────────────────────────────────────────────────
namespace crypto {

// ── Base64 (standard variant, matches Python's base64.b64encode) ──────────────

std::string to_base64(const unsigned char* data, std::size_t len) {
    const std::size_t b64_len =
        sodium_base64_encoded_len(len, sodium_base64_VARIANT_ORIGINAL);
    std::string result(b64_len, '\0');
    sodium_bin2base64(result.data(), b64_len, data, len,
                      sodium_base64_VARIANT_ORIGINAL);
    result.resize(b64_len - 1);  // drop null terminator sodium includes in the count
    return result;
}

std::string to_base64(const std::vector<unsigned char>& v) {
    return to_base64(v.data(), v.size());
}

std::vector<unsigned char> from_base64(const std::string& b64) {
    std::vector<unsigned char> bin(b64.size());
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

struct Keypair {
    std::vector<unsigned char> pub;   // 32-byte X25519 u-coordinate — share freely
    std::vector<unsigned char> priv;  // 32-byte scalar — NEVER transmit
};

Keypair generate_keypair() {
    Keypair kp;
    kp.pub.resize(crypto_box_PUBLICKEYBYTES);   // 32
    kp.priv.resize(crypto_box_SECRETKEYBYTES);  // 32
    crypto_box_keypair(kp.pub.data(), kp.priv.data());
    return kp;
}

// ── HKDF-SHA256 (RFC 5869) ────────────────────────────────────────────────────
//
// Implemented from libsodium's HMAC-SHA256 primitives.
// These two functions reproduce the identical output to Python's:
//   cryptography.hazmat.primitives.kdf.hkdf.HKDF(SHA256, length, salt, info).derive(ikm)
//
// HKDF-Extract: PRK = HMAC-SHA256(key=salt, data=ikm)
static std::vector<unsigned char> hkdf_extract(
    const std::vector<unsigned char>& salt,
    const std::vector<unsigned char>& ikm)
{
    std::vector<unsigned char> prk(crypto_auth_hmacsha256_BYTES); // 32
    crypto_auth_hmacsha256_state st;
    crypto_auth_hmacsha256_init  (&st, salt.data(), salt.size());
    crypto_auth_hmacsha256_update(&st, ikm.data(),  ikm.size());
    crypto_auth_hmacsha256_final (&st, prk.data());
    return prk;
}

// HKDF-Expand: OKM = T(1) ‖ T(2) ‖ … truncated to `length` bytes.
//   T(0) = ""
//   T(i) = HMAC-SHA256(PRK, T(i-1) ‖ info ‖ i)
static std::vector<unsigned char> hkdf_expand(
    const std::vector<unsigned char>& prk,
    const std::vector<unsigned char>& info,
    std::size_t length)
{
    const std::size_t H = crypto_auth_hmacsha256_BYTES; // 32
    std::vector<unsigned char> okm;
    okm.reserve(length + H);
    std::vector<unsigned char> t_prev; // T(i-1), empty for first round
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

// Default application context — must equal the Python backend's default b"secure-messenger".
static const std::vector<unsigned char> HPKE_INFO = {
    's','e','c','u','r','e','-','m','e','s','s','e','n','g','e','r'
};

// ── HPKE Mode_Auth ────────────────────────────────────────────────────────────

struct EncryptedMessage {
    std::string ciphertext_b64;    // base64(AES-256-GCM ciphertext + 16-byte tag)
    std::string nonce_b64;         // base64(12-byte HKDF-derived nonce) — needed by API
    std::string encrypted_key_b64; // base64(32-byte ephemeral public key ek_pub)
                                   // NOT a wrapped symmetric key — the symmetric key
                                   // is DERIVED by the recipient via HKDF, never stored.
};

// Encrypt `plaintext` for `recipient_pub` in HPKE Mode_Auth.
//
// Mirrors Python's encapsulate(recipient_public_key, sender_private_key, plaintext, info).
// The C++ and Python outputs are cross-decryptable as long as the same info string is used.
//
// Requires AES-NI (or equivalent) hardware — check crypto_aead_aes256gcm_is_available()
// before calling.
EncryptedMessage hpke_encapsulate(
    const std::string& plaintext,
    const std::vector<unsigned char>& recipient_pub,   // 32-byte X25519 public key
    const std::vector<unsigned char>& sender_priv,     // 32-byte X25519 private key
    const std::vector<unsigned char>& info = HPKE_INFO)
{
    if (recipient_pub.size() != 32)
        throw std::runtime_error("recipient_pub must be 32 bytes");
    if (sender_priv.size() != 32)
        throw std::runtime_error("sender_priv must be 32 bytes");

    // 1. Generate ephemeral X25519 keypair.
    //    ek_priv is used for one DH computation and then zeroed — it never leaves
    //    this function and does not appear in the output.
    std::vector<unsigned char> ek_priv(32), ek_pub(32);
    randombytes_buf(ek_priv.data(), 32);
    // Compute ek_pub = ek_priv * G (Curve25519 base-point multiplication).
    crypto_scalarmult_curve25519_base(ek_pub.data(), ek_priv.data());

    // 2. Two DH computations — the core of Mode_Auth.
    //    crypto_scalarmult_curve25519 applies Curve25519 clamping internally,
    //    identical to Python's X25519PrivateKey.exchange() behaviour.
    std::vector<unsigned char> dh1(32), dh2(32);
    if (crypto_scalarmult_curve25519(dh1.data(), ek_priv.data(),    recipient_pub.data()) != 0 ||
        crypto_scalarmult_curve25519(dh2.data(), sender_priv.data(), recipient_pub.data()) != 0) {
        sodium_memzero(ek_priv.data(), ek_priv.size());
        throw std::runtime_error("DH computation failed — low-order point?");
    }

    // 3. HKDF-SHA256 key schedule (identical to Python's _derive_key_and_nonce).
    //    ikm  = dh1 ‖ dh2
    //    salt = ek_pub  (binds derivation to this specific encapsulation)
    //    info = b"secure-messenger"  (domain separation)
    //    OKM  = 44 bytes: key = OKM[0:32], nonce = OKM[32:44]
    std::vector<unsigned char> ikm;
    ikm.insert(ikm.end(), dh1.begin(), dh1.end());
    ikm.insert(ikm.end(), dh2.begin(), dh2.end());
    auto prk = hkdf_extract(ek_pub, ikm);
    auto okm = hkdf_expand(prk, info, 44);

    std::vector<unsigned char> aes_key(okm.begin(),      okm.begin() + 32);
    std::vector<unsigned char> nonce  (okm.begin() + 32, okm.begin() + 44);

    // 4. AES-256-GCM encrypt (matches Python's AESGCM(aes_key).encrypt(nonce, pt, None)).
    const auto* pt = reinterpret_cast<const unsigned char*>(plaintext.data());
    std::vector<unsigned char> ct(plaintext.size() + crypto_aead_aes256gcm_ABYTES);
    unsigned long long ct_len = 0;
    crypto_aead_aes256gcm_encrypt(
        ct.data(), &ct_len,
        pt, plaintext.size(),
        nullptr, 0,  // no associated data (matches Python's None)
        nullptr,     // nsec — unused
        nonce.data(), aes_key.data());
    ct.resize(ct_len);

    // 5. Zero all sensitive intermediate values before they leave the stack.
    sodium_memzero(ek_priv.data(), ek_priv.size());
    sodium_memzero(dh1.data(), dh1.size());
    sodium_memzero(dh2.data(), dh2.size());
    sodium_memzero(prk.data(), prk.size());
    sodium_memzero(okm.data(), okm.size());
    sodium_memzero(aes_key.data(), aes_key.size());

    // encrypted_key carries the ephemeral public key (ek_pub), not a wrapped
    // message key.  The recipient re-derives the actual symmetric key via HKDF.
    return EncryptedMessage{to_base64(ct), to_base64(nonce), to_base64(ek_pub)};
}

// Decrypt a message produced by hpke_encapsulate() (or Python's encapsulate()).
//
// Mirrors Python's decapsulate(recipient_private_key, sender_public_key, ciphertext,
//                               encapsulated_key, info).
//
// `ciphertext_blob_b64` is the packed blob stored by the server:
//   base64(nonce_12_bytes ‖ aes_gcm_ciphertext_with_tag)
// The 12-byte nonce is stripped before decryption; the recipient re-derives it
// from the key schedule and does not trust the stored value.
//
// `enc_key_b64` is the 32-byte ephemeral public key (ek_pub) stored in the
// `encrypted_key` field by the sender.
std::optional<std::string> hpke_decapsulate(
    const std::string& ciphertext_blob_b64,
    const std::string& enc_key_b64,
    const std::vector<unsigned char>& recipient_priv,  // 32-byte private key
    const std::vector<unsigned char>& sender_pub,      // 32-byte static public key
    const std::vector<unsigned char>& info = HPKE_INFO)
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

        // Strip the stored nonce prefix — we re-derive the nonce from the key schedule
        // and do not trust the transmitted value.
        std::vector<unsigned char> ct(blob.begin() + 12, blob.end());

        // Replicate the sender's DH computations (X25519 commutativity).
        std::vector<unsigned char> dh1(32), dh2(32);
        if (crypto_scalarmult_curve25519(dh1.data(), recipient_priv.data(), ek_pub.data())    != 0 ||
            crypto_scalarmult_curve25519(dh2.data(), recipient_priv.data(), sender_pub.data()) != 0) {
            std::cerr << "DH computation failed\n";
            return std::nullopt;
        }

        // Re-run the identical HKDF key schedule.
        std::vector<unsigned char> ikm;
        ikm.insert(ikm.end(), dh1.begin(), dh1.end());
        ikm.insert(ikm.end(), dh2.begin(), dh2.end());
        auto prk = hkdf_extract(ek_pub, ikm);
        auto okm = hkdf_expand(prk, info, 44);

        std::vector<unsigned char> aes_key(okm.begin(),      okm.begin() + 32);
        std::vector<unsigned char> nonce  (okm.begin() + 32, okm.begin() + 44);

        if (ct.size() < crypto_aead_aes256gcm_ABYTES) {
            std::cerr << "Ciphertext too short for GCM tag\n";
            return std::nullopt;
        }
        std::vector<unsigned char> plaintext(ct.size() - crypto_aead_aes256gcm_ABYTES);
        unsigned long long pt_len = 0;
        int rc = crypto_aead_aes256gcm_decrypt(
            plaintext.data(), &pt_len,
            nullptr,
            ct.data(), ct.size(),
            nullptr, 0,
            nonce.data(), aes_key.data());

        sodium_memzero(dh1.data(),     dh1.size());
        sodium_memzero(dh2.data(),     dh2.size());
        sodium_memzero(prk.data(),     prk.size());
        sodium_memzero(okm.data(),     okm.size());
        sodium_memzero(aes_key.data(), aes_key.size());

        if (rc != 0) {
            std::cerr << "AES-256-GCM authentication failed.\n"
                      << "The message was not produced by the expected sender, "
                         "or was tampered with.\n";
            return std::nullopt;
        }
        plaintext.resize(pt_len);
        return std::string(reinterpret_cast<char*>(plaintext.data()), pt_len);
    } catch (const std::exception& e) {
        std::cerr << "hpke_decapsulate error: " << e.what() << "\n";
        return std::nullopt;
    }
}

} // namespace crypto

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
    std::system("stty -echo");
    std::string pw;
    std::getline(std::cin, pw);
    std::system("stty echo");
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

} // namespace cli

// ── Session state ─────────────────────────────────────────────────────────────

struct Session {
    Client           client;
    MessageStore     inbox;
    MessageStore     sent;
    crypto::Keypair  keypair;
    bool             has_keypair{false};
};

// ── Actions ───────────────────────────────────────────────────────────────────

static void do_register(Session& sess) {
    cli::header("Register new account");
    const std::string username = cli::prompt("Username : ");
    const std::string email    = cli::prompt("Email    : ");
    const std::string password = cli::prompt_password("Password : ");
    if (sess.client.register_user(username, email, password)) {
        std::cout << "Account created. You can now log in.\n";
    }
}

static bool do_login(Session& sess) {
    cli::header("Login");
    const std::string username = cli::prompt("Username : ");
    const std::string password = cli::prompt_password("Password : ");
    if (sess.client.login(username, password)) {
        std::cout << "Logged in as " << username << ".\n";
        return true;
    }
    return false;
}

static void do_generate_keypair(Session& sess) {
    cli::header("Generate & upload keypair");
    sess.keypair     = crypto::generate_keypair();
    sess.has_keypair = true;

    const std::string pub_b64  = crypto::to_base64(sess.keypair.pub);
    std::string       priv_b64 = crypto::to_base64(sess.keypair.priv);

    std::cout << "Public key (base64, 32 bytes):\n  " << pub_b64 << "\n\n"
              << "WARNING: the private key is held in memory only.\n"
              << "         Save it before exiting.\n\n"
              << "Private key (base64) — KEEP SECRET:\n  " << priv_b64 << "\n\n";

    sodium_memzero(priv_b64.data(), priv_b64.size());

    std::cout << "Uploading public key to server…\n";
    if (sess.client.upload_public_key(pub_b64)) {
        std::cout << "Uploaded. Other users can now send HPKE-encrypted messages to you.\n";
    }
}

static void do_import_keypair(Session& sess) {
    cli::header("Import existing keypair");
    const std::string pub_b64  = cli::prompt("Public key  (base64): ");
    const std::string priv_b64 = cli::prompt("Private key (base64): ");
    try {
        sess.keypair.pub  = crypto::from_base64(pub_b64);
        sess.keypair.priv = crypto::from_base64(priv_b64);
        if (sess.keypair.pub.size()  != 32 ||
            sess.keypair.priv.size() != 32) {
            std::cout << "Each key must decode to exactly 32 bytes.\n";
            sess.has_keypair = false;
            return;
        }
        sess.has_keypair = true;
        std::cout << "Keypair imported.\n";
    } catch (const std::exception& e) {
        std::cout << "Error: " << e.what() << "\n";
        sess.has_keypair = false;
    }
}

static void do_view_inbox(Session& sess) {
    cli::header("Inbox");
    auto messages = sess.client.get_inbox();
    if (messages.empty()) { std::cout << "  (no messages)\n"; return; }
    sess.inbox.replace_all(std::move(messages));
    for (const auto& m : sess.inbox.sorted_by_date_desc()) {
        const std::string mark = m.is_read() ? " " : "*";
        const std::string from = m.sender_username() ? *m.sender_username() : "(unknown)";
        const std::string subj = m.subject() ? *m.subject() : "(no subject)";
        std::cout << "[" << mark << "] #" << m.id()
                  << "  from: " << from
                  << "  subject: " << subj
                  << "  (" << m.created_at() << ")\n";
    }
}

static void do_view_sent(Session& sess) {
    cli::header("Sent messages");
    auto messages = sess.client.get_sent();
    if (messages.empty()) { std::cout << "  (no sent messages)\n"; return; }
    sess.sent.replace_all(std::move(messages));
    for (const auto& m : sess.sent.sorted_by_date_desc()) {
        const std::string subj = m.subject() ? *m.subject() : "(no subject)";
        std::cout << "  #" << m.id()
                  << "  subject: " << subj
                  << "  (" << m.created_at() << ")\n";
    }
}

static void do_send_message(Session& sess) {
    cli::header("Send message (HPKE Mode_Auth)");

    if (!sess.has_keypair) {
        std::cout << "You need a keypair before sending — your private key is the\n"
                  << "authentication proof that this message is from you.\n"
                  << "Generate or import one first (options 5/6).\n";
        return;
    }
    if (!crypto_aead_aes256gcm_is_available()) {
        std::cout << "AES-NI is not available on this CPU.\n"
                  << "HPKE Mode_Auth requires hardware AES-256-GCM.\n";
        return;
    }

    const std::string recipient = cli::prompt("Recipient username: ");
    auto user_opt = sess.client.get_user(recipient);
    if (!user_opt || !user_opt->has_public_key()) {
        std::cout << "User not found or has no public key.\n";
        return;
    }

    std::vector<unsigned char> recipient_pub;
    try {
        recipient_pub = crypto::from_base64(*user_opt->public_key());
    } catch (...) {
        std::cout << "Failed to decode recipient's public key.\n"; return;
    }
    if (recipient_pub.size() != 32) {
        std::cout << "Recipient's public key is not 32 bytes.\n"; return;
    }

    const std::string subject   = cli::prompt("Subject (Enter to skip): ");
    const std::string plaintext = cli::prompt("Message: ");
    if (plaintext.empty()) { std::cout << "Empty message — aborted.\n"; return; }

    std::cout << "Encrypting with HPKE Mode_Auth…\n";
    crypto::EncryptedMessage enc;
    try {
        enc = crypto::hpke_encapsulate(plaintext, recipient_pub, sess.keypair.priv);
    } catch (const std::exception& e) {
        std::cout << "Encryption error: " << e.what() << "\n"; return;
    }

    const std::optional<std::string> subj_opt =
        subject.empty() ? std::nullopt : std::optional<std::string>{subject};

    if (sess.client.send_message(recipient,
                                  enc.ciphertext_b64,
                                  enc.nonce_b64,
                                  subj_opt,
                                  enc.encrypted_key_b64)) {
        std::cout << "Message sent.\n";
    }
}

static void do_download_message(Session& sess) {
    cli::header("Download / read message");
    const std::string id_str = cli::prompt("Message ID: ");
    int id = 0;
    try { id = std::stoi(id_str); } catch (...) {
        std::cout << "Invalid ID.\n"; return;
    }

    auto msg_opt = sess.client.download_message(id);
    if (!msg_opt) {
        std::cout << "Message not found or access denied.\n"; return;
    }
    const auto& msg = *msg_opt;

    std::cout << "\nFrom       : "
              << (msg.sender_username() ? *msg.sender_username() : "(unknown)")
              << "\nSent at    : " << msg.created_at()
              << "\nSubject    : " << (msg.subject() ? *msg.subject() : "(none)")
              << "\nAAD        : "
              << (msg.associated_data() ? *msg.associated_data() : "(none)")
              << "\n";

    if (!msg.ciphertext() || !msg.encrypted_key()) {
        std::cout << "\nMissing ciphertext or encrypted_key — cannot decrypt.\n"; return;
    }
    if (!sess.has_keypair) {
        std::cout << "\nNo local keypair — import it first (option 6) and retry.\n"; return;
    }
    if (!crypto_aead_aes256gcm_is_available()) {
        std::cout << "\nAES-NI not available — cannot run HPKE decapsulation.\n"; return;
    }

    // Fetch the sender's static public key for Mode_Auth verification.
    // Decryption fails with a GCM tag error if the wrong sender key is used —
    // this is the implicit authentication guarantee of HPKE Mode_Auth.
    const std::string sender_name =
        msg.sender_username() ? *msg.sender_username() : "";
    if (sender_name.empty()) {
        std::cout << "\nSender username unknown — cannot look up their public key.\n"; return;
    }

    auto sender_user = sess.client.get_user(sender_name);
    if (!sender_user || !sender_user->has_public_key()) {
        std::cout << "\nCould not retrieve sender '" << sender_name
                  << "' public key — they may have deleted their account or key.\n"; return;
    }

    std::vector<unsigned char> sender_pub;
    try {
        sender_pub = crypto::from_base64(*sender_user->public_key());
    } catch (...) {
        std::cout << "Failed to decode sender's public key.\n"; return;
    }
    if (sender_pub.size() != 32) {
        std::cout << "Sender's public key is not 32 bytes.\n"; return;
    }

    std::cout << "\nDecapsulating (HPKE Mode_Auth)…\n";
    auto plaintext = crypto::hpke_decapsulate(
        *msg.ciphertext(),    // base64(nonce_12 ‖ ct_with_tag) — server packed blob
        *msg.encrypted_key(), // base64(ek_pub) — the ephemeral public key
        sess.keypair.priv,
        sender_pub
    );

    if (plaintext) {
        std::cout << "\n┌── Message ─────────────────────────────\n"
                  << *plaintext << "\n"
                  << "└────────────────────────────────────────\n";
    } else {
        std::cout << "Decryption failed.  Possible causes:\n"
                  << "  • Message was encrypted with a different scheme (not HPKE Mode_Auth)\n"
                  << "  • Sender has rotated their key since sending — TOFU mismatch\n"
                  << "  • Ciphertext was tampered with\n"
                  << "  • Wrong keypair loaded\n";
    }
}

static void do_delete_message(Session& sess) {
    cli::header("Delete message");
    const std::string id_str = cli::prompt("Message ID to delete: ");
    int id = 0;
    try { id = std::stoi(id_str); } catch (...) {
        std::cout << "Invalid ID.\n"; return;
    }
    if (sess.client.delete_message(id))
        std::cout << "Message #" << id << " deleted.\n";
}

static void do_lookup_user(Session& sess) {
    cli::header("Look up user");
    const std::string username = cli::prompt("Username: ");
    auto user_opt = sess.client.get_user(username);
    if (!user_opt) { std::cout << "User not found or inactive.\n"; return; }
    std::cout << "  id      : " << user_opt->id()
              << "\n  username: " << user_opt->username()
              << "\n  pub_key : "
              << (user_opt->has_public_key() ? *user_opt->public_key() : "(none)")
              << "\n";
}

static void do_unread_summary(Session& sess) {
    const auto unread = sess.inbox.unread();
    if (!unread.empty())
        std::cout << "\n  [!] " << unread.size() << " unread message(s)\n";
}

// ── Main menu loop ────────────────────────────────────────────────────────────

static void run_logged_in(Session& sess) {
    const std::string heading = "Logged in as: " + sess.client.logged_in_as();
    while (true) {
        do_unread_summary(sess);
        const int choice = cli::menu_choice(heading, {
            "View inbox",
            "View sent messages",
            "Send a message",
            "Download / read a message",
            "Delete a message",
            "Generate & upload new keypair",
            "Import existing keypair",
            "Look up a user",
            "Logout",
            "Exit"
        });
        switch (choice) {
            case 1:  do_view_inbox(sess);      break;
            case 2:  do_view_sent(sess);       break;
            case 3:  do_send_message(sess);    break;
            case 4:  do_download_message(sess);break;
            case 5:  do_delete_message(sess);  break;
            case 6:  do_generate_keypair(sess);break;
            case 7:  do_import_keypair(sess);  break;
            case 8:  do_lookup_user(sess);     break;
            case 9:
                sess.client.logout();
                std::cout << "Logged out.\n";
                return;
            case 10:
                sess.client.logout();
                std::exit(0);
        }
    }
}

// ── Entry point ───────────────────────────────────────────────────────────────

int main(int argc, char* argv[]) {
    if (sodium_init() < 0) {
        std::cerr << "Failed to initialise libsodium.\n"; return 1;
    }

    ClientConfig cfg;
    if (argc >= 2) cfg.base_url = argv[1];

    std::cout << "=== Secure Messenger CLI (HPKE Mode_Auth) ===\n"
              << "Server: " << cfg.base_url << "\n";

    if (!crypto_aead_aes256gcm_is_available()) {
        std::cout << "\nWARNING: AES-NI hardware support not detected.\n"
                  << "Encryption and decryption will not be available.\n"
                  << "You can still register, log in, and browse messages.\n\n";
    }

    Session sess{Client{cfg}};

    while (true) {
        const int choice = cli::menu_choice("Main Menu", {
            "Login",
            "Register new account",
            "Exit"
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
