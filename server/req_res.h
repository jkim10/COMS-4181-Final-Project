#include <iostream>
#include <string>
#include <regex>

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
	
	std::string username;
	std::string password;
	std::string payload;
	
	std::string str() const {
		return username + "\n" + password + "\n" + payload;
	}
	
	bool verify() const {
		// TODO: implement password checking!
		return true;
	}
};

PASS_AUTH_REQ PASS_AUTH_REQ::parse_pass_auth_req(const std::string& raw_req_str) {
	static const std::string regex_str = R"(^([a-z]+)\r?\n([!-~]+)\r?\n)";
	const std::regex reg(regex_str);
	std::smatch sm;
	
	if(!std::regex_search(raw_req_str, sm, reg) || sm.size() != 3) {
		throw std::runtime_error(std::string("Pass Auth Req Regex No Match!\n"));
		//std::cerr << "Pass Auth Req Regex No Match" << std::endl;
		//return PASS_AUTH_REQ();
	}
	
	return {sm[1].str(), sm[2].str(), sm.suffix()};
}

}