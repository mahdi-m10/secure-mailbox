#include "MessageStore.hpp"
#include <algorithm>
#include <iterator>
#include <utility>

void MessageStore::add(Message msg) {
    const int id = msg.id();
    auto it = id_to_index_.find(id);
    if (it != id_to_index_.end()) {
        // Upsert: replace the existing entry
        messages_[it->second] = std::move(msg);
    } else {
        id_to_index_[id] = messages_.size();
        messages_.push_back(std::move(msg));
    }
}

void MessageStore::replace_all(std::vector<Message> messages) {
    messages_ = std::move(messages);
    id_to_index_.clear();
    for (std::size_t i = 0; i < messages_.size(); ++i) {
        id_to_index_[messages_[i].id()] = i;
    }
}

void MessageStore::update(const Message& msg) {
    auto it = id_to_index_.find(msg.id());
    if (it != id_to_index_.end()) {
        messages_[it->second] = msg;
    }
}

void MessageStore::clear() {
    messages_.clear();
    id_to_index_.clear();
}

std::optional<std::reference_wrapper<const Message>>
MessageStore::find_by_id(int id) const {
    auto it = id_to_index_.find(id);
    if (it == id_to_index_.end()) return std::nullopt;
    return std::cref(messages_[it->second]);
}

// Returns a copy sorted newest-first.
// ISO-8601 strings from the backend ("2024-01-15T12:34:56") compare
// lexicographically in the same order as chronologically, so plain string
// comparison is correct without any date parsing.
std::vector<Message> MessageStore::sorted_by_date_desc() const {
    std::vector<Message> result = messages_;
    std::sort(result.begin(), result.end(), [](const Message& a, const Message& b) {
        return a.created_at() > b.created_at();
    });
    return result;
}

std::vector<Message> MessageStore::unread() const {
    std::vector<Message> result;
    std::copy_if(messages_.cbegin(), messages_.cend(), std::back_inserter(result),
                 [](const Message& m) { return !m.is_read() && !m.is_deleted(); });
    return result;
}

std::vector<Message> MessageStore::from_sender(const std::string& sender_username) const {
    std::vector<Message> result;
    std::copy_if(messages_.cbegin(), messages_.cend(), std::back_inserter(result),
                 [&sender_username](const Message& m) {
                     return m.sender_username().has_value() &&
                            *m.sender_username() == sender_username;
                 });
    return result;
}
