#pragma once

#include <string>

namespace my {

std::string get_file_contents(const char* filename);

void set_file_contents(const char* filename, std::string contents);

//std::string create_tmp_file(std::string contents);

char* hash_password(const char* password, const char* hash);

bool verify_password(const std::string& password, const std::string& hash);

std::string sign_client_csr(const std::string& csr);

void fork_exec(const char *path, char *const argv[]);

}