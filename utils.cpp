#include "utils.h"
#include "config.h"
#include <cstdlib>
#include <fstream>
#include <sstream>
#include <cstring>
#include <iostream>

std::string run_command(const std::string& cmd) {
    // Command Injection (CWE-78)
    char buffer[128];
    std::string result;
    FILE* pipe = popen(cmd.c_str(), "r");   // опасно!
    if (!pipe) return "ERROR";
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        result += buffer;
    }
    pclose(pipe);
    return result;
}

std::string read_file(const std::string& path) {
    // Path Traversal (CWE-22) — нет проверки пути
    std::ifstream file(path);
    if (!file) return "File not found";
    std::stringstream ss;
    ss << file.rdbuf();
    return ss.str();
}

void save_file(const std::string& filename, const std::string& content) {
    // Path Traversal при сохранении
    std::string full_path = Config::UPLOAD_DIR + filename;
    std::ofstream out(full_path);
    if (out) {
        out << content;
    }
}

std::string encrypt(const std::string& data) {
    // Очень слабое "шифрование" (CWE-327 / CWE-326)
    std::string result = data;
    for (char& c : result) {
        c ^= 0x42;
    }
    return result;
}
