#include <fstream>
#include <sstream>
#include <system_error>
#include <cerrno>
#include <unistd.h>
#include <cstring>

#include "utils.h"

namespace my {

std::string get_file_contents(const char* filename) {
	std::ifstream in(filename, std::ios::in | std::ios::binary);
	if (!in) {
		throw std::system_error(errno, std::generic_category());
	}
	std::ostringstream contents;
	contents << in.rdbuf();
	in.close();
	return contents.str();
}

void set_file_contents(const char* filename, std::string contents) {
	std::ofstream out(filename, std::ios::out | std::ios::trunc | std::ios::binary);
	if (!out) {
		throw std::system_error(errno, std::generic_category());
	}
	out << contents;
	out.close();
}

bool verify_password(const std::string& password, const std::string& hash) {
	char* new_hash = crypt(password.c_str(), hash.c_str());
	if (new_hash == NULL) {
		throw std::system_error(errno, std::generic_category());
	}
	return (std::strncmp(new_hash, hash.c_str(), hash.size()) == 0);
}

}