#include "Message.hpp"
#include <utility>

Message::Message(int                        id,
                 std::optional<int>         sender_id,
                 std::optional<std::string> sender_username,
                 std::optional<std::string> subject,
                 bool                       is_read,
                 bool                       is_deleted,
                 std::string                created_at)
    : id_{id}
    , sender_id_{sender_id}
    , sender_username_{std::move(sender_username)}
    , subject_{std::move(subject)}
    , is_read_{is_read}
    , is_deleted_{is_deleted}
    , created_at_{std::move(created_at)}
{}
