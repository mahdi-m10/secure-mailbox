cmake_minimum_required(VERSION 3.16)
project(SecureMessengerClient LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# ── Dependencies ──────────────────────────────────────────────────────────────

find_package(CURL REQUIRED)

find_package(PkgConfig REQUIRED)
pkg_check_modules(SODIUM REQUIRED libsodium)

# nlohmann/json ships its own CMake package when installed via nlohmann-json3-dev
find_package(nlohmann_json REQUIRED)

# ── Executable ────────────────────────────────────────────────────────────────

add_executable(secure_messenger
    src/main.cpp
    src/User.cpp
    src/Message.cpp
    src/Client.cpp
    src/MessageStore.cpp
)

target_include_directories(secure_messenger
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${SODIUM_INCLUDE_DIRS}
)

target_link_libraries(secure_messenger
    PRIVATE
        CURL::libcurl
        ${SODIUM_LIBRARIES}
        nlohmann_json::nlohmann_json
)

target_compile_options(secure_messenger
    PRIVATE
        -Wall
        -Wextra
        -Wpedantic
)

message(STATUS "libsodium: ${SODIUM_VERSION}")
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
