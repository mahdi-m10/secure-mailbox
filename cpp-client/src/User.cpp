#include "User.hpp"
#include <utility>

User::User(int id, std::string username, std::optional<std::string> public_key)
    : id_{id}
    , username_{std::move(username)}
    , public_key_{std::move(public_key)}
{}
