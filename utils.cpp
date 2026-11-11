#include "utils.h"
#include "config.h"
#include <cstdlib>
#include <fstream>
#include <sstream>
#include <cstring>
#include <iostream>
#include <sodium.h>
#include <array>
#include <stdexcept>

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
    auto path = valid_path(filename);
    if (!path) return "Access denied";
    std::ifstream file(path);    
    if (!file) return "File not found";
    std::stringstream ss;
    ss << file.rdbuf();
    return ss.str();
}

bool save_file(const std::string& filename, const std::string& content) {
    auto path = valid_path(filename);
    if (!path) return false;
    std::ofstream out(*path);
    if (out) {
        out << content;
        return out.good();
    }
    return false;
}

std::optional<std::string> encrypt(const std::string& data) {
    if (sodium_init() < 0) return std::nullopt;
    unsigned char key[crypto_secretbox_KEYBYTES];
    std::ifstream file(".key", std::ios::binary);
    if (!file.read(reinterpret_cast<char*>(key), sizeof key))
        return std::nullopt;
    std::string result(
        crypto_secretbox_NONCEBYTES + crypto_secretbox_MACBYTES + data.size(), '\0'
    );
    auto* nonce = reinterpret_cast<unsigned char*>(result.data());
    randombytes_buf(nonce, crypto_secretbox_NONCEBYTES);
    crypto_secretbox_easy(
        nonce + crypto_secretbox_NONCEBYTES,
        reinterpret_cast<const unsigned char*>(data.data()),
        data.size(), nonce, key
    );
    sodium_memzero(key, sizeof key);
    return result;
}

std::optional<std::string> decrypt(const std::string& data) {
    if (sodium_init() < 0) return std::nullopt;
    if (data.size() < crypto_secretbox_NONCEBYTES + crypto_secretbox_MACBYTES)
        return std::nullopt;
    unsigned char key[crypto_secretbox_KEYBYTES];
    std::ifstream file(".key", std::ios::binary);
    if (!file.read(reinterpret_cast<char*>(key), sizeof key))
        return std::nullopt;
    auto* nonce = reinterpret_cast<const unsigned char*>(data.data());
    auto* ciphertext = nonce + crypto_secretbox_NONCEBYTES;
    std::string result(
        data.size() - crypto_secretbox_NONCEBYTES - crypto_secretbox_MACBYTES,
        '\0'
    );
    int status = crypto_secretbox_open_easy(
        reinterpret_cast<unsigned char*>(result.data()),
        ciphertext,
        data.size() - crypto_secretbox_NONCEBYTES,
        nonce,
        key
    );
    sodium_memzero(key, sizeof key);
    if (status != 0) return std::nullopt;
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