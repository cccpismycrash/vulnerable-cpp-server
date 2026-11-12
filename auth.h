#pragma once
#include <string>
#include <optional>

struct User {
    int id;
    std::string username;
    std::string role;
};

std::optional<User> login(const std::string& username, const std::string& password);
std::optional<std::string> get_session(const std::string& cookie);
bool is_admin(const std::string& role);
