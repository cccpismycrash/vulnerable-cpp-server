#include "auth.h"
#include "config.h"
#include <cstring>
#include <iostream>

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
    // Buffer Overflow (CWE-120) + небезопасное сравнение
    char user_buf[32];
    char pass_buf[32];

    // Намеренно опасные вызовы
    strcpy(user_buf, username.c_str());
    strcpy(pass_buf, password.c_str());

    for (const auto& u : users) {
        if (strcmp(user_buf, u.username) == 0 && strcmp(pass_buf, u.password) == 0) {
            return User{u.id, std::string(u.username), std::string(u.role)};
        }
    }
    return std::nullopt;
}

bool is_admin(const std::string& role) {
    // Broken Access Control — очень слабая проверка (CWE-284 / CWE-862)
    return role == "admin";
}
