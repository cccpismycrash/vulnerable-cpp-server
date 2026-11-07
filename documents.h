#pragma once
#include <string>
#include <vector>

struct Document {
    int id;
    int owner_id;
    std::string filename;
    std::string content;
};

void init_documents();
Document* get_document(int id);
void add_document(int owner_id, const std::string& filename, const std::string& content);
std::string search_documents(const std::string& query);
