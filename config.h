#pragma once
#include <string>

namespace Config {
    // ВНИМАНИЕ: намеренно уязвимые значения для лабораторной работы
    const std::string SECRET_KEY = "hardcoded_super_secret_key_12345";   // CWE-798
    const std::string ADMIN_PASSWORD = "Admin@2024";                     // CWE-798
    const std::string DB_FILE = "users.db";
    const std::string UPLOAD_DIR = "uploads/";
    const int PORT = 8080;
    const bool DEBUG = true;
}
