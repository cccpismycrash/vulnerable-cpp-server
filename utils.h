#pragma once
#include <string>

std::string run_command(const std::string& cmd);
std::string read_file(const std::string& path);
bool save_file(const std::string& filename, const std::string& content);
std::optional<std::string> encrypt(const std::string& data);
std::optional<fs::path> valid_path(const std::string& filename)