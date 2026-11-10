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

Document* get_document(int id, const User* user) {
    if (user == nullptr)
        return nullptr;

    for (auto& d : docs) {
        if (d.id == id && d.owner_id == user->id) {
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

    char buffer[256];

    snprintf(buffer, sizeof(buffer), "%s", query.c_str());
    
    char result_buf[512];
    snprintf(result_buf, sizeof(result_buf), "%s", query.c_str());

    std::string result = "Search results for: ";
    result += result_buf;
    return result;
}
