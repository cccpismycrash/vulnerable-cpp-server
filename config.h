#pragma once
#include <string>
#include <fstream>

namespace Config {

    inline std::string SECRET_KEY;
    inline std::string ADMIN_PASSWORD;
    const std::string DB_FILE = "users.db";
    const std::string UPLOAD_DIR = "uploads/";
    const int PORT = 8080;
    const bool DEBUG = true;

    inline int load() {
        std::ifstream file("secrets.conf");

        if (!file) {
            return 1;
        }

        if (
            !std::getline(file, SECRET_KEY) ||
            !std::getline(file, ADMIN_PASSWORD) ||
            SECRET_KEY.empty() ||
            ADMIN_PASSWORD.empty()
        ) {
            return 1;
        }

        return 0;
    }
}
