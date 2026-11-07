#pragma once
#include <string>

std::string run_command(const std::string& cmd);
std::string read_file(const std::string& path);
void save_file(const std::string& filename, const std::string& content);
std::string encrypt(const std::string& data);
