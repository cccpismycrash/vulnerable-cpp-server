#include "httplib.h"
#include "config.h"
#include "auth.h"
#include "documents.h"
#include "utils.h"
#include <iostream>
#include <map>
#include <string>
#include <filesystem>
#include <sstream>

namespace fs = std::filesystem;

std::map<std::string, User> sessions;   // session_id → user

int main() {

    if (Config::load() != 0) {
        return 1;
    }

    // Создаём папку для загрузок
    fs::create_directories(Config::UPLOAD_DIR);

    init_documents();
    httplib::Server svr;

    // ---------- Логин ----------
    svr.Post("/login", [](const httplib::Request& req, httplib::Response& res) {
        std::string username = req.get_param_value("username");
        std::string password = req.get_param_value("password");

        auto user = login(username, password);
        if (user) {
            std::string sid = "sess_" + std::to_string(user->id) + "_" + Config::SECRET_KEY;
            sessions[sid] = *user;
            res.set_header("Set-Cookie", "session=" + sid + "; Path=/");
            res.set_content("Login successful. Role: " + user->role + "\nSession: " + sid, "text/plain");
        } else {
            res.status = 401;
            res.set_content("Invalid credentials", "text/plain");
        }
    });

    // ---------- Просмотр документа (IDOR) ----------
    svr.Get(R"(/document/(\d+))", [](const httplib::Request& req, httplib::Response& res) {
        try {
            int id = std::stoi(req.matches[1].str());
            
            // идентифицируем пользователя по сессионной куке
            auto sid = get_session(req.get_header_value("Cookie"));
            if (!sid || sessions.find(*sid) == sessions.end()) {
                res.status = 401;
                return;
            }
            auto it = sessions.find(*sid);
            User user = it->second;
            auto* doc = get_document(id, &user);
            if (doc) {
                if (doc->owner_id != user.id && user.role != "admin") {
                    res.status = 403;
                    res.set_content("Forbidden", "text/plain");
                    return;
                }
                res.set_content("File: " + doc->filename + "\nOwner ID: " + std::to_string(doc->owner_id) +
                                "\n\n" + doc->content, "text/plain");
            } else {
                res.status = 404;
                res.set_content("Not found", "text/plain");
            }
        } catch (...) {
            res.status = 400;
            res.set_content("Invalid ID", "text/plain");
        }
    });

    // ---------- Поиск (Format String) ----------
    svr.Get("/search", [](const httplib::Request& req, httplib::Response& res) {
        auto sid = get_session(req.get_header_value("Cookie"));
        if (!sid || sessions.find(*sid) == sessions.end()) {
            res.status = 401;
            return;
        }
        std::string q = req.get_param_value("q");
        if (q.empty()) q = "empty";
        res.set_content(search_documents(q), "text/html");
    });

    // ---------- Загрузка файла (Path Traversal) ----------
    svr.Post("/upload", [](const httplib::Request& req, httplib::Response& res) {
        auto sid = get_session(req.get_header_value("Cookie"));
        if (!sid || sessions.find(*sid) == sessions.end()) {
            res.status = 401;
            return;
        }
        std::string filename = req.get_param_value("filename");
        std::string content = req.get_param_value("content");
        if (filename.empty()) {
            res.status = 400;
            res.set_content("filename required", "text/plain");
            return;
        }
        if (!save_file(filename, content)) {
            res.status = 403;
            res.set_content("Access denied or save failed", "text/plain");
            return;
        }
        res.set_content("Uploaded: " + filename, "text/plain");
    });

    // ---------- Админская команда (Command Injection) ----------
    svr.Get("/admin/cmd", [](const httplib::Request& req, httplib::Response& res) {
        auto sid = get_session(req.get_header_value("Cookie"));
        if (!sid || sessions.find(*sid) == sessions.end()) {
            res.status = 401;
            return;
        }
        std::string cmd = req.get_param_value("cmd");
        if (cmd.empty()) cmd = "id";
        std::string output = run_command(cmd);
        res.set_content(output, "text/plain");
    });

    // ---------- Чтение произвольного файла ----------
    svr.Get("/read", [](const httplib::Request& req, httplib::Response& res) {
        auto sid = get_session(req.get_header_value("Cookie"));
        if (!sid || sessions.find(*sid) == sessions.end()) {
            res.status = 401;
            return;
        }
        std::string path = req.get_param_value("path");
        if (path.empty()) {
            res.status = 400;
            res.set_content("path required", "text/plain");
            return;
        }
        res.set_content(read_file(path), "text/plain");
    });

    // ---------- Сохранение файла с шифрованием ----------
    svr.Post("/upload-encrypted", [](const auto& req, auto& res) {
        auto sid = get_session(req.get_header_value("Cookie"));
        if (!sid || sessions.find(*sid) == sessions.end()) {
            res.status = 401;
            return;
        }
        std::string filename = req.get_param_value("filename");
        std::string content = req.get_param_value("content");
        if (filename.empty()) {
            res.status = 400;
            return;
        }
        auto encrypted = encrypt(content);
        if (!encrypted || !save_file(filename, *encrypted)) {
            res.status = 400;
            res.set_content("Encryption or saving failed", "text/plain");
            return;
        }
        res.set_content("Encrypted file saved", "text/plain");
    });
    
    // ---------- Чтение с дешифрованием ----------
    svr.Get("/read-encrypted", [](const auto& req, auto& res) {
        auto sid = get_session(req.get_header_value("Cookie"));
        if (!sid || sessions.find(*sid) == sessions.end()) {
            res.status = 401;
            return;
        }
        std::string filename = req.get_param_value("path");
        if (filename.empty()) {
            res.status = 400;
            return;
        }
        auto content = read_file(filename);
        if (!content) {
            res.status = 404;
            res.set_content("File not found or access denied", "text/plain");
            return;
        }
        auto decrypted = decrypt(*content);
        if (!decrypted) {
            res.status = 400;
            res.set_content("Decryption failed", "text/plain");
            return;
        }
        res.set_content(*decrypted, "text/plain");
    });

    // ---------- Простая главная ----------
    svr.Get("/", [](const httplib::Request&, httplib::Response& res) {
        res.set_content(
            "Vulnerable C++ Document Server (Lab)\n\n"
            "Endpoints:\n"
            "  POST /login              username=&password=\n"
            "  GET  /document/<id>\n"
            "  GET  /search?q=\n"
            "  POST /upload             filename=&content=\n"
            "  GET  /admin/cmd?cmd=\n"
            "  GET  /read?path=\n",
            "  POST /upload-encrypted   filename=&content=\n",
            "  GET  /read-encrypted\n",
            "text/plain");
    });

    std::cout << "========================================\n"
              << " Vulnerable C++ Server started\n"
              << " Port: " << Config::PORT << "\n"
              << "========================================\n";
    svr.listen("0.0.0.0", Config::PORT);
}
