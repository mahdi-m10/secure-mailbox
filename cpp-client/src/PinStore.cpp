#include "PinStore.hpp"
#include <chrono>
#include <ctime>
#include <fstream>
#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

namespace {

std::string now_iso8601() {
    const auto now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    char buf[32];
    std::tm tm_utc{};
    gmtime_r(&now, &tm_utc);
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm_utc);
    return buf;
}

} // namespace

PinStore::PinStore(std::filesystem::path path) : path_(std::move(path)) {
    load();
}

void PinStore::load() {
    std::ifstream in(path_);
    if (!in) return;  // no pins yet — empty store
    try {
        json j;
        in >> j;
        for (const auto& [peer, entry] : j.items()) {
            pins_[peer] = Entry{
                entry.at("public_key").get<std::string>(),
                entry.value("pinned_at", ""),
            };
        }
    } catch (const std::exception& e) {
        // A corrupt pin file must not silently become "no pins" — that would
        // let an attacker reset trust by damaging the file.  Refuse to start.
        std::cerr << "FATAL: TOFU pin file is corrupt: " << path_ << "\n"
                  << "       (" << e.what() << ")\n"
                  << "Inspect or remove the file manually before continuing.\n";
        throw;
    }
}

void PinStore::save() const {
    json j = json::object();
    for (const auto& [peer, entry] : pins_) {
        j[peer] = {
            {"public_key", entry.public_key_b64},
            {"pinned_at",  entry.pinned_at},
        };
    }

    std::error_code ec;
    std::filesystem::create_directories(path_.parent_path(), ec);

    std::ofstream out(path_, std::ios::trunc);
    if (!out) {
        std::cerr << "Warning: cannot persist TOFU pins to " << path_ << "\n";
        return;
    }
    out << j.dump(2) << "\n";

    std::filesystem::permissions(path_,
        std::filesystem::perms::owner_read | std::filesystem::perms::owner_write,
        std::filesystem::perm_options::replace, ec);
}

PinStore::CheckResult PinStore::check(const std::string& peer,
                                      const std::string& key_b64) const {
    const auto it = pins_.find(peer);
    if (it == pins_.end()) {
        return CheckResult{Status::FirstUse, "", ""};
    }
    if (it->second.public_key_b64 == key_b64) {
        return CheckResult{Status::Match, it->second.public_key_b64, it->second.pinned_at};
    }
    return CheckResult{Status::Mismatch, it->second.public_key_b64, it->second.pinned_at};
}

void PinStore::pin(const std::string& peer, const std::string& key_b64) {
    pins_[peer] = Entry{key_b64, now_iso8601()};
    save();
}
