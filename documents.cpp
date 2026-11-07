#include "documents.h"
#include <vector>
#include <cstring>
#include <cstdio>

static std::vector<Document> docs;

void init_documents() {
    docs.clear();
    docs.push_back({1, 1, "secret.txt", "Top secret admin data - confidential"});
    docs.push_back({2, 2, "alice_notes.txt", "Alice private notes"});
    docs.push_back({3, 3, "bob_data.txt", "Bob information"});
}

Document* get_document(int id) {
    // IDOR (CWE-639) — нет проверки владельца / прав доступа
    for (auto& d : docs) {
        if (d.id == id) {
            return &d;
        }
    }
    return nullptr;
}

void add_document(int owner_id, const std::string& filename, const std::string& content) {
    static int next_id = 4;
    docs.push_back({next_id++, owner_id, filename, content});
}

std::string search_documents(const std::string& query) {
    // Format String Vulnerability (CWE-134)
    char buffer[256];
    // Намеренно опасно: пользовательский ввод как format-string
    snprintf(buffer, sizeof(buffer), query.c_str());  // всё равно опасно при %n и т.п.
    
    // Более явная уязвимость:
    char result_buf[512];
    sprintf(result_buf, query.c_str());   // CWE-134

    std::string result = "Search results for: ";
    result += result_buf;
    return result;
}
