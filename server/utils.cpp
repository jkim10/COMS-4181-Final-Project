#include <fstream>
#include <sstream>
#include <system_error>
#include <cerrno>
#include <unistd.h>
#include <cstring>

#include "utils.h"

namespace my {

std::string get_file_contents(const char* filename)
{
  std::ifstream in(filename, std::ios::in | std::ios::binary);
  if (in)
  {
    std::ostringstream contents;
    contents << in.rdbuf();
    in.close();
    return(contents.str());
  }
  throw std::system_error(errno, std::generic_category());
}

bool verify_password(const std::string& password, const std::string& hash) {
	char* new_hash = crypt(password.c_str(), hash.c_str());
	if (new_hash == NULL) {
		throw std::system_error(errno, std::generic_category());
	}
	return (std::strncmp(new_hash, hash.c_str(), hash.size()) == 0);
}

}