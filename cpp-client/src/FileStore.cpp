#include "FileStore.hpp"
#include <algorithm>
#include <iterator>
#include <utility>

void FileStore::add(File file) {
    const int id = file.id();
    auto it = id_to_index_.find(id);
    if (it != id_to_index_.end()) {
        // Upsert: replace the existing entry
        files_[it->second] = std::move(file);
    } else {
        id_to_index_[id] = files_.size();
        files_.push_back(std::move(file));
    }
}

void FileStore::replace_all(std::vector<File> files) {
    files_ = std::move(files);
    id_to_index_.clear();
    for (std::size_t i = 0; i < files_.size(); ++i) {
        id_to_index_[files_[i].id()] = i;
    }
}

void FileStore::update(const File& file) {
    auto it = id_to_index_.find(file.id());
    if (it != id_to_index_.end()) {
        files_[it->second] = file;
    }
}

void FileStore::clear() {
    files_.clear();
    id_to_index_.clear();
}

std::optional<std::reference_wrapper<const File>>
FileStore::find_by_id(int id) const {
    auto it = id_to_index_.find(id);
    if (it == id_to_index_.end()) return std::nullopt;
    return std::cref(files_[it->second]);
}

// Returns a copy sorted newest-first.
// ISO-8601 strings from the backend ("2024-01-15T12:34:56") compare
// lexicographically in the same order as chronologically, so plain string
// comparison is correct without any date parsing.
std::vector<File> FileStore::sorted_by_date_desc() const {
    std::vector<File> result = files_;
    std::sort(result.begin(), result.end(), [](const File& a, const File& b) {
        return a.created_at() > b.created_at();
    });
    return result;
}

std::vector<File> FileStore::unread() const {
    std::vector<File> result;
    std::copy_if(files_.cbegin(), files_.cend(), std::back_inserter(result),
                 [](const File& f) { return !f.is_read() && !f.is_deleted(); });
    return result;
}

std::vector<File> FileStore::from_owner(const std::string& owner_username) const {
    std::vector<File> result;
    std::copy_if(files_.cbegin(), files_.cend(), std::back_inserter(result),
                 [&owner_username](const File& f) {
                     return f.owner_username().has_value() &&
                            *f.owner_username() == owner_username;
                 });
    return result;
}
