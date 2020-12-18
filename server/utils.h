#pragma once

#include <string>

namespace my {

std::string get_file_contents(const char* filename);

char* hash_password(const char* password, const char* hash);

bool verify_password(const std::string& password, const std::string& hash);

}