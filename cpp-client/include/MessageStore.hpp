#pragma once
#include <functional>
#include <map>
#include <optional>
#include <string>
#include <vector>
#include "Message.hpp"

// In-memory message cache combining:
//   - std::vector for ordered iteration and cache-friendly access
//   - std::map for O(log n) lookup by message id
//
// STL algorithms (std::sort, std::copy_if) power the filtering / sorting
// helpers so no hand-rolled loops are needed at the call site.
class MessageStore {
public:
    // Add a message.  If a message with the same id already exists it is
    // replaced (upsert semantics) so a re-download doesn't create duplicates.
    void add(Message msg);

    // Atomically replace the entire cache (used after a fresh inbox fetch).
    void replace_all(std::vector<Message> messages);

    // Update an existing entry in-place (e.g. after marking as read or
    // after a full download populates the ciphertext fields).
    void update(const Message& msg);

    void clear();

    std::size_t size()  const noexcept { return messages_.size(); }
    bool        empty() const noexcept { return messages_.empty(); }

    // O(log n) lookup via the id index.
    // Returns a const reference wrapper to avoid an unnecessary copy.
    std::optional<std::reference_wrapper<const Message>> find_by_id(int id) const;

    // ── STL-powered views ─────────────────────────────────────────────────────
    // ISO-8601 timestamps sort lexicographically == chronologically, so string
    // comparison is sufficient.
    std::vector<Message> sorted_by_date_desc() const;

    // Messages that are not yet read and not soft-deleted.
    std::vector<Message> unread() const;

    // All messages from a specific sender username.
    std::vector<Message> from_sender(const std::string& sender_username) const;

    const std::vector<Message>& all() const noexcept { return messages_; }

private:
    std::vector<Message>     messages_;
    std::map<int, std::size_t> id_to_index_;  // message id → index into messages_
};
