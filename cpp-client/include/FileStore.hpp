#pragma once
#include <functional>
#include <map>
#include <optional>
#include <string>
#include <vector>
#include "File.hpp"

// In-memory file-listing cache combining:
//   - std::vector for ordered iteration and cache-friendly access
//   - std::map for O(log n) lookup by file id
//
// STL algorithms (std::sort, std::copy_if) power the filtering / sorting
// helpers so no hand-rolled loops are needed at the call site.
class FileStore {
public:
    // Add a file.  If a file with the same id already exists it is replaced
    // (upsert semantics) so a re-download doesn't create duplicates.
    void add(File file);

    // Atomically replace the entire cache (used after a fresh listing fetch).
    void replace_all(std::vector<File> files);

    // Update an existing entry in-place (e.g. after marking as read or
    // after a full download populates the ciphertext fields).
    void update(const File& file);

    void clear();

    std::size_t size()  const noexcept { return files_.size(); }
    bool        empty() const noexcept { return files_.empty(); }

    // O(log n) lookup via the id index.
    // Returns a const reference wrapper to avoid an unnecessary copy.
    std::optional<std::reference_wrapper<const File>> find_by_id(int id) const;

    // ── STL-powered views ─────────────────────────────────────────────────────
    // ISO-8601 timestamps sort lexicographically == chronologically, so string
    // comparison is sufficient.
    std::vector<File> sorted_by_date_desc() const;

    // Files that are not yet read and not soft-deleted.
    std::vector<File> unread() const;

    // All files owned/uploaded by a specific username.
    std::vector<File> from_owner(const std::string& owner_username) const;

    const std::vector<File>& all() const noexcept { return files_; }

private:
    std::vector<File>          files_;
    std::map<int, std::size_t> id_to_index_;  // file id → index into files_
};
