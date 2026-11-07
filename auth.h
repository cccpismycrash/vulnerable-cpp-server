#pragma once
#include <string>
#include <optional>

struct User {
    int id;
    std::string username;
    std::string role;
};

std::optional<User> login(const std::string& username, const std::string& password);
bool is_admin(const std::string& role);
