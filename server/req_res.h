#pragma once

#include <iostream>
#include <string>
#include <regex>
#include <vector>
#include <unordered_map>
#include <unistd.h>

#include "utils.h"

namespace my {

using namespace std;

class PASS_AUTH_REQ {
public:
	static PASS_AUTH_REQ parse_pass_auth_req(const std::string& raw_req_str);
	
	PASS_AUTH_REQ(const std::string& req_str) : PASS_AUTH_REQ(PASS_AUTH_REQ::parse_pass_auth_req(req_str)) {}
	PASS_AUTH_REQ(const std::string& username, const std::string& password, const std::string& payload)
	: username{username}, password{password}, payload{payload} {}
	PASS_AUTH_REQ(const PASS_AUTH_REQ&) = default;
	PASS_AUTH_REQ(PASS_AUTH_REQ&&) = default;
	PASS_AUTH_REQ() = default;
	
	const std::string username;
	const std::string password;
	const std::string payload;
	
	std::string str() const {
		return username + "\n" + password + "\n" + payload + "\n";
	}
	
	bool verify() const {
		try {
			const std::string hash = PASS_AUTH_REQ::hpw_dict.at(username);
			std::cerr << "Verifying: " << username << " " << password << " " << hash << std::endl;
			return my::verify_password(password, hash);
		} catch (const std::out_of_range& ex) {
			return false;
		}
	}

private:
	static const constexpr char* HPW_FILE_PATH = "users.txt";
	static std::unordered_map<std::string, std::string> hpw_dict;
};

std::unordered_map<std::string, std::string> PASS_AUTH_REQ::hpw_dict = []() -> std::unordered_map<std::string, std::string> {
	static const std::string regex_str = R"(([a-z]+) (\$\d\$[!-~]{16}\$[!-~]{86})\r?\n?)";
	static const std::regex reg(regex_str);
	
	const std::string raw_hpw_str = my::get_file_contents(PASS_AUTH_REQ::HPW_FILE_PATH);
	
	auto hpw_begin = 
		std::sregex_iterator(raw_hpw_str.begin(), raw_hpw_str.end(), reg);
	auto hpw_end = std::sregex_iterator();
	std::unordered_map<std::string, std::string> hpw_dict;
	
	for (auto i = hpw_begin; i != hpw_end; ++i) {                                            
		std::smatch sm = *i;
		if (sm.size() != 3) {
			std::cerr << "Hashed Passwords File Line Regex No Match: " << sm.str() << std::endl;
			continue;
		}
		hpw_dict.insert({sm[1].str(), sm[2].str()});
	}
	
	return hpw_dict;
}();

PASS_AUTH_REQ PASS_AUTH_REQ::parse_pass_auth_req(const std::string& raw_req_str) {
	static const std::string regex_str = R"(^([a-z]+)\r?\n([!-~]+)\r?\n)";
	const std::regex reg(regex_str);
	std::smatch sm;
	
	if(!std::regex_search(raw_req_str, sm, reg) || sm.size() != 3) {
		throw std::runtime_error(std::string("Pass Auth Req Regex No Match!\n"));
	}
	
	return {sm[1].str(), sm[2].str(), sm.suffix()};
}

}
