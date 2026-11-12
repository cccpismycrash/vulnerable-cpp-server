#include "auth.h"
#include "config.h"
#include <cstring>
#include <iostream>
#include <sstream>

// Имитация "базы" пользователей в памяти
struct DbUser {
    const char* username;
    const char* password;
    const char* role;
    int id;
};

static DbUser users[] = {
    {"admin", "admin123", "admin", 1},
    {"alice", "password", "user", 2},
    {"bob", "qwerty", "user", 3}
};

std::optional<User> login(const std::string& username, const std::string& password) {
    char user_buf[32];
    char pass_buf[32];

    if (
        username.size() >= sizeof(user_buf) ||
        password.size() >= sizeof(pass_buf)
    ) {
        return std::nullopt;
    }

    std::memcpy(user_buf, username.c_str(), username.size() + 1);
    std::memcpy(pass_buf, password.c_str(), password.size() + 1);

    for (const auto& u : users) {
        if (strcmp(user_buf, u.username) == 0 && strcmp(pass_buf, u.password) == 0) {
            return User{u.id, std::string(u.username), std::string(u.role)};
        }
    }
    return std::nullopt;
}

std::optional<std::string> get_session(const std::string& cookie) {
    if (cookie.empty()) return std::nullopt;

    std::istringstream stream(cookie);
    std::string key, value;

    std::getline(stream, key, '=');
    std::getline(stream, value, ';');

    if (key != "session" || value.empty())
        return std::nullopt;

    return value;
}

bool is_admin(const std::string& role) {
    // Broken Access Control — очень слабая проверка (CWE-284 / CWE-862)
    return role == "admin";
}
