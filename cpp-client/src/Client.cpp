#include "Client.hpp"
#include <iostream>
#include <stdexcept>
#include <string>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

// ── Helpers ───────────────────────────────────────────────────────────────────

// Convenience: pull an optional<T> out of a JSON field that may be null/absent.
template <typename T>
static std::optional<T> opt(const json& j, const char* key) {
    if (!j.contains(key) || j[key].is_null()) return std::nullopt;
    return j[key].get<T>();
}

// Print the "detail" field from a non-2xx response body (FastAPI error format).
static void print_error(long code, const std::string& body) {
    std::cerr << "[HTTP " << code << "] ";
    try {
        auto j = json::parse(body);
        if (j.contains("detail")) {
            std::cerr << j["detail"].dump() << "\n";
            return;
        }
    } catch (...) {}
    std::cerr << body << "\n";
}

static File parse_file_item(const json& j) {
    File::Fields f;
    f.id                 = j.at("id").get<int>();
    f.owner_id           = opt<int>(j, "owner_id");
    f.owner_username     = opt<std::string>(j, "owner_username");
    f.recipient_username = opt<std::string>(j, "recipient_username");
    f.subject            = opt<std::string>(j, "subject");
    f.filename           = opt<std::string>(j, "filename");
    f.content_type       = opt<std::string>(j, "content_type");
    f.size_bytes         = opt<std::int64_t>(j, "size_bytes");
    f.is_read            = j.at("is_read").get<bool>();
    f.is_deleted         = j.value("is_deleted", false);   // absent in download responses
    f.is_forwarded       = opt<bool>(j, "is_forwarded");
    f.created_at         = j.at("created_at").get<std::string>();
    return File{std::move(f)};
}

// ── libcurl write callback ────────────────────────────────────────────────────

size_t Client::write_callback(char* ptr, size_t size, size_t nmemb, void* userdata) {
    auto* body = static_cast<std::string*>(userdata);
    body->append(ptr, size * nmemb);
    return size * nmemb;
}

// ── Constructor ───────────────────────────────────────────────────────────────

Client::Client(ClientConfig config)
    : config_{std::move(config)}
    , curl_{curl_easy_init()}
{
    if (!curl_) {
        throw std::runtime_error("curl_easy_init() failed — is libcurl installed?");
    }
}

// ── Private: generic request helper ──────────────────────────────────────────

Client::HttpResponse Client::request(const std::string& method,
                                      const std::string& path,
                                      const std::string& body,
                                      bool               form_encoded) {
    HttpResponse response;

    // Reset all previous options so state cannot bleed between calls.
    curl_easy_reset(curl_.get());

    const std::string url = config_.base_url + path;
    curl_easy_setopt(curl_.get(), CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl_.get(), CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl_.get(), CURLOPT_WRITEDATA, &response.body);

    if (!config_.verify_ssl) {
        curl_easy_setopt(curl_.get(), CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl_.get(), CURLOPT_SSL_VERIFYHOST, 0L);
    }

    // Build the header list (freed at the end of the function).
    curl_slist* headers = nullptr;
    if (form_encoded) {
        headers = curl_slist_append(headers, "Content-Type: application/x-www-form-urlencoded");
    } else {
        headers = curl_slist_append(headers, "Content-Type: application/json");
    }
    headers = curl_slist_append(headers, "Accept: application/json");
    if (!access_token_.empty()) {
        const std::string auth = "Authorization: Bearer " + access_token_;
        headers = curl_slist_append(headers, auth.c_str());
    }
    curl_easy_setopt(curl_.get(), CURLOPT_HTTPHEADER, headers);

    // Set method-specific options.
    if (method == "POST") {
        curl_easy_setopt(curl_.get(), CURLOPT_POST, 1L);
        curl_easy_setopt(curl_.get(), CURLOPT_POSTFIELDS, body.c_str());
        curl_easy_setopt(curl_.get(), CURLOPT_POSTFIELDSIZE,
                         static_cast<long>(body.size()));
    } else if (method == "PUT") {
        curl_easy_setopt(curl_.get(), CURLOPT_CUSTOMREQUEST, "PUT");
        curl_easy_setopt(curl_.get(), CURLOPT_POSTFIELDS, body.c_str());
        curl_easy_setopt(curl_.get(), CURLOPT_POSTFIELDSIZE,
                         static_cast<long>(body.size()));
    } else if (method == "DELETE") {
        curl_easy_setopt(curl_.get(), CURLOPT_CUSTOMREQUEST, "DELETE");
    }
    // GET is the default after curl_easy_reset.

    const CURLcode res = curl_easy_perform(curl_.get());
    curl_slist_free_all(headers);

    if (res != CURLE_OK) {
        std::cerr << "[curl] " << curl_easy_strerror(res) << "\n";
        return response;
    }
    curl_easy_getinfo(curl_.get(), CURLINFO_RESPONSE_CODE, &response.status_code);
    return response;
}

std::string Client::url_encode(const std::string& value) const {
    char* enc = curl_easy_escape(curl_.get(), value.c_str(),
                                 static_cast<int>(value.size()));
    if (!enc) return value;
    std::string result(enc);
    curl_free(enc);
    return result;
}

// ── Auth ──────────────────────────────────────────────────────────────────────

bool Client::login(const std::string& username, const std::string& password) {
    json body;
    body["username"] = username;
    body["password"] = password;

    auto resp = request("POST", "/auth/login", body.dump());

    if (resp.status_code != 200) {
        print_error(resp.status_code, resp.body);
        return false;
    }
    try {
        auto j = json::parse(resp.body);
        access_token_  = j.at("access_token").get<std::string>();
        refresh_token_ = opt<std::string>(j, "refresh_token").value_or("");
        username_      = username;
        return true;
    } catch (const std::exception& e) {
        std::cerr << "Failed to parse login response: " << e.what() << "\n";
        return false;
    }
}

bool Client::logout() {
    if (!is_logged_in()) return false;
    json body;
    body["refresh_token"] = refresh_token_;
    auto resp = request("POST", "/auth/logout", body.dump());
    if (resp.status_code != 200) {
        print_error(resp.status_code, resp.body);
        return false;
    }
    access_token_.clear();
    refresh_token_.clear();
    username_.clear();
    return true;
}

bool Client::register_user(const std::string& username,
                            const std::string& email,
                            const std::string& password) {
    json body;
    body["username"] = username;
    body["email"]    = email;
    body["password"] = password;

    auto resp = request("POST", "/auth/register", body.dump());
    if (resp.status_code != 201) {
        print_error(resp.status_code, resp.body);
        return false;
    }
    return true;
}

// ── Key discovery ─────────────────────────────────────────────────────────────

std::optional<User> Client::get_user(const std::string& username) {
    auto resp = request("GET", "/users/" + url_encode(username));
    if (resp.status_code == 404) return std::nullopt;
    if (resp.status_code != 200) {
        print_error(resp.status_code, resp.body);
        return std::nullopt;
    }
    try {
        auto j = json::parse(resp.body);
        return User{
            j.at("id").get<int>(),
            j.at("username").get<std::string>(),
            opt<std::string>(j, "public_key")
        };
    } catch (const std::exception& e) {
        std::cerr << "Failed to parse user: " << e.what() << "\n";
        return std::nullopt;
    }
}

std::vector<User> Client::list_users(int skip, int limit) {
    const std::string path =
        "/users?skip=" + std::to_string(skip) + "&limit=" + std::to_string(limit);
    auto resp = request("GET", path);
    if (resp.status_code != 200) {
        print_error(resp.status_code, resp.body);
        return {};
    }
    std::vector<User> users;
    try {
        auto arr = json::parse(resp.body);
        users.reserve(arr.size());
        for (const auto& j : arr) {
            users.emplace_back(
                j.at("id").get<int>(),
                j.at("username").get<std::string>(),
                opt<std::string>(j, "public_key")
            );
        }
    } catch (const std::exception& e) {
        std::cerr << "Failed to parse user list: " << e.what() << "\n";
    }
    return users;
}

bool Client::upload_public_key(const std::string& public_key_b64) {
    json body;
    body["public_key"] = public_key_b64;
    auto resp = request("POST", "/users/keys", body.dump());
    if (resp.status_code != 200) {
        print_error(resp.status_code, resp.body);
        return false;
    }
    return true;
}

// ── Files ─────────────────────────────────────────────────────────────────────

std::optional<int> Client::upload_file(const std::string& recipient_username,
                                       const UploadPayload& payload) {
    json body;
    body["recipient_username"] = recipient_username;
    body["ciphertext"]         = payload.ciphertext_b64;
    body["nonce"]              = payload.nonce_b64;
    body["encrypted_key"]      = payload.encrypted_key_b64;
    body["associated_data"]    = payload.associated_data;
    if (payload.filename)     body["filename"]     = *payload.filename;
    if (payload.content_type) body["content_type"] = *payload.content_type;
    if (payload.size_bytes)   body["size_bytes"]   = *payload.size_bytes;
    if (payload.subject)      body["subject"]      = *payload.subject;

    auto resp = request("POST", "/files/upload", body.dump());
    if (resp.status_code != 201) {
        print_error(resp.status_code, resp.body);
        return std::nullopt;
    }
    try {
        return json::parse(resp.body).at("id").get<int>();
    } catch (const std::exception& e) {
        std::cerr << "Failed to parse upload response: " << e.what() << "\n";
        return std::nullopt;
    }
}

std::vector<File> Client::get_file_listing(const std::string& endpoint,
                                           int skip, int limit) {
    const std::string path =
        endpoint + "?skip=" + std::to_string(skip) + "&limit=" + std::to_string(limit);
    auto resp = request("GET", path);
    if (resp.status_code != 200) {
        print_error(resp.status_code, resp.body);
        return {};
    }
    std::vector<File> files;
    try {
        auto arr = json::parse(resp.body);
        files.reserve(arr.size());
        for (const auto& j : arr) {
            files.push_back(parse_file_item(j));
        }
    } catch (const std::exception& e) {
        std::cerr << "Failed to parse file listing: " << e.what() << "\n";
    }
    return files;
}

std::vector<File> Client::get_shared(int skip, int limit) {
    return get_file_listing("/files/shared", skip, limit);
}

std::vector<File> Client::get_owned(int skip, int limit) {
    return get_file_listing("/files/owned", skip, limit);
}

std::optional<File> Client::download_file(int file_id) {
    const std::string path = "/files/" + std::to_string(file_id) + "/download";
    auto resp = request("GET", path);
    if (resp.status_code == 404) return std::nullopt;
    if (resp.status_code != 200) {
        print_error(resp.status_code, resp.body);
        return std::nullopt;
    }
    try {
        auto j = json::parse(resp.body);
        File file = parse_file_item(j);
        if (j.contains("ciphertext") && !j["ciphertext"].is_null())
            file.set_ciphertext(j["ciphertext"].get<std::string>());
        if (j.contains("nonce") && !j["nonce"].is_null())
            file.set_nonce(j["nonce"].get<std::string>());
        if (j.contains("associated_data") && !j["associated_data"].is_null())
            file.set_associated_data(j["associated_data"].get<std::string>());
        if (j.contains("encrypted_key") && !j["encrypted_key"].is_null())
            file.set_encrypted_key(j["encrypted_key"].get<std::string>());
        if (j.contains("integrity_hash") && !j["integrity_hash"].is_null())
            file.set_integrity_hash(j["integrity_hash"].get<std::string>());
        file.mark_read();
        return file;
    } catch (const std::exception& e) {
        std::cerr << "Failed to parse downloaded file: " << e.what() << "\n";
        return std::nullopt;
    }
}

bool Client::delete_file(int file_id) {
    const std::string path = "/files/" + std::to_string(file_id);
    auto resp = request("DELETE", path);
    if (resp.status_code != 200) {
        print_error(resp.status_code, resp.body);
        return false;
    }
    return true;
}

Client::ReceiptStatus Client::get_receipt_status(int file_id) {
    // Informational / fail-open: any failure just yields queried=false, never
    // an error to the caller. The blockchain-proof endpoint returns
    //   receipt:        live MessageReceipt.getReceipt() {exists, block_number}
    //   receipt_tx_hash: the posting tx recorded in the DB, if any
    ReceiptStatus st;
    const std::string path = "/files/" + std::to_string(file_id) + "/blockchain-proof";
    auto resp = request("GET", path);
    if (resp.status_code != 200) return st;

    try {
        auto j = json::parse(resp.body);
        st.queried = true;
        st.tx_hash = opt<std::string>(j, "receipt_tx_hash").value_or("");
        if (j.contains("receipt") && j["receipt"].is_object()) {
            const auto& r = j["receipt"];
            st.confirmed = r.value("exists", false);
            if (st.confirmed) st.block_number = r.value("block_number", std::int64_t{0});
        }
    } catch (const std::exception&) {
        st.queried = false;
    }
    return st;
}

bool Client::share_file(int file_id,
                        const std::string& recipient_username,
                        const std::string& new_ciphertext_b64,
                        const std::string& new_nonce_b64,
                        const std::string& new_encrypted_key_b64) {
    json body;
    body["recipient_username"] = recipient_username;
    body["new_ciphertext"]     = new_ciphertext_b64;
    body["new_nonce"]          = new_nonce_b64;
    body["new_encrypted_key"]  = new_encrypted_key_b64;

    const std::string path = "/files/" + std::to_string(file_id) + "/share";
    auto resp = request("POST", path, body.dump());
    if (resp.status_code != 200 && resp.status_code != 201) {
        print_error(resp.status_code, resp.body);
        return false;
    }
    return true;
}

bool Client::revoke_access(int file_id,
                           const std::optional<std::string>& recipient_username) {
    json body = json::object();
    if (recipient_username) body["recipient_username"] = *recipient_username;

    const std::string path = "/files/" + std::to_string(file_id) + "/revoke";
    auto resp = request("POST", path, body.dump());
    if (resp.status_code != 200) {
        print_error(resp.status_code, resp.body);
        return false;
    }
    return true;
}
