#include "utils.h"
#include "config.h"
#include <cstdlib>
#include <fstream>
#include <sstream>
#include <cstring>
#include <iostream>

std::string run_command(const std::string& cmd) {

    if (cmd == "whoami") {
        return "admin\n";
    }
    if (cmd == "id") {
        return "uid=1000(admin) gid=1000(admin)\n";
    }
    if (cmd == "pwd") {
        return "/home/admin\n";
    }
    if (cmd == "ls") {
        return "documents\nuploads\nconfig.txt\n";
    }
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

namespace fs = std::filesystem;
std::optional<fs::path> valid_path(const std::string& filename) {
    try {
        fs::path root = fs::canonical(Config::UPLOAD_DIR);
        fs::path target = fs::weakly_canonical(root / filename);
        if (target.parent_path() != root)
            return std::nullopt;
        return target;
    }
    catch (const fs::filesystem_error&) {
        return std::nullopt;
    }
}