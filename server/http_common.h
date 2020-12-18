#pragma once

#include <iostream>
#include <string>
#include <regex>
#include <vector>

namespace my {

using namespace std;

class HTTP_DATA {
public:
	virtual std::string str() const = 0;
	virtual ~HTTP_DATA() = default;
};

const ostream& operator<<(ostream& os, const HTTP_DATA& data) {
	os << data.str();
	return os;
}

class HTTP_HEADER: HTTP_DATA {
public:
	static std::vector<HTTP_HEADER> parse_http_header(const std::string& raw_header_str);
	
	//HTTP_HEADER(const std::string& header_str) : HTTP_HEADER(HTTP_HEADER::parse_http_header(header_str)) {}
	HTTP_HEADER(const std::string& name, const std::string& value)
	: name{name}, value{value} {}
	HTTP_HEADER(const HTTP_HEADER&) = default;
	HTTP_HEADER(HTTP_HEADER&&) = default;
	HTTP_HEADER() = default;
	
	std::string name;
	std::string value;
	
	std::string str() const {
		return name + ": " + value + "\n";
	}
};

class HTTP_REQ: HTTP_DATA {
public:
	static HTTP_REQ parse_http_req(const std::string& raw_req_str);
	
	HTTP_REQ(const std::string& req_str) : HTTP_REQ(HTTP_REQ::parse_http_req(req_str)) {}
	HTTP_REQ(const std::string& method, const std::string& endpoint,
			 std::vector<HTTP_HEADER> headers, const std::string& body)
	: method{method}, endpoint{endpoint}, headers{headers}, body{body} {}
	HTTP_REQ(const HTTP_REQ&) = default;
	HTTP_REQ(HTTP_REQ&&) = default;
	HTTP_REQ() = default;
	
	std::string method;
	std::string endpoint;
	std::vector<HTTP_HEADER> headers;
	std::string body;
	
	std::string str() const {
		std::string req_str;
		req_str += method + " /" + endpoint + " HTTP/1.0\r\n";
		for (auto& header : headers) {
			req_str += header.str();
		}
		req_str += "\r\n";
		req_str += body;
		return req_str;
	}
};

class HTTP_RES: HTTP_DATA {
public:
	static HTTP_RES parse_http_res(const std::string& raw_res_str);
	static std::string get_status_msg(const int& status_code);
	
	HTTP_RES(const std::string& res_str) : HTTP_RES(HTTP_RES::parse_http_res(res_str)) {}
	HTTP_RES(const std::string& status_code, const std::string& status_msg,
			 std::vector<HTTP_HEADER> headers, const std::string& body)
	: status_code{status_code}, status_msg{status_msg}, headers{headers}, body{body} {}
	HTTP_RES(const int& status_code, const std::string& body)
	: status_code{std::to_string(status_code)},
	  status_msg{HTTP_RES::get_status_msg(status_code)},
	  headers{{{"Content-length", std::to_string(body.size())}}},
	  body{body}
	{}
	HTTP_RES(const HTTP_RES&) = default;
	HTTP_RES(HTTP_RES&&) = default;
	HTTP_RES() = default;
	
	std::string status_code;
	std::string status_msg;
	std::vector<HTTP_HEADER> headers;
	std::string body;
	
	std::string str() const {
		std::string res_str;
		res_str += "HTTP/1.0 " + status_code + " " + status_msg + "\r\n";
		for (auto& header : headers) {
			res_str += header.str();
		}
		res_str += "\r\n";
		res_str += body;
		return res_str;
	}
};

std::vector<HTTP_HEADER> HTTP_HEADER::parse_http_header(const std::string& raw_header_str) {
	static const std::string regex_str = R"(([a-zA-Z-]+) *: *([!-~ \t]*[!-~])[\t ]*\r?\n)";
	static const std::regex reg(regex_str);
	
	auto headers_begin = 
		std::sregex_iterator(raw_header_str.begin(), raw_header_str.end(), reg);
	auto headers_end = std::sregex_iterator();
	std::vector<HTTP_HEADER> headers;
	
	for (std::sregex_iterator i = headers_begin; i != headers_end; ++i) {                                            
		std::smatch sm = *i;
		if (sm.size() != 3) {
			std::cerr << "HTTP Header Regex No Match: " << sm.str() << std::endl;
			continue;
		}
		headers.push_back({sm[1].str(), sm[2].str()});
	}
	
	return headers;
}

HTTP_REQ HTTP_REQ::parse_http_req(const std::string& raw_req_str) {
	static const std::string regex_str = 
		R"(^(GET|POST) \/([a-z]+)\/? HTTP\/\d.\d\r?\n((?:[a-zA-Z-]+: *[!-~ \t]+\r?\n)*)\r?\n)";
	static const std::regex reg(regex_str);
	std::smatch sm;
	
	if(!std::regex_search(raw_req_str, sm, reg) || sm.size() != 4) {
		throw std::runtime_error(std::string("HTTP Request Regex No Match!"));
	}
	
	return {sm[1].str(), sm[2].str(), HTTP_HEADER::parse_http_header(sm[3].str()), sm.suffix()};
}

HTTP_RES HTTP_RES::parse_http_res(const std::string& raw_res_str) {
	static const std::string regex_str = 
		R"(^HTTP\/\d.\d (\d{3}) ([a-zA-Z -]+)\r?\n((?:[a-zA-Z-]+ *: *[!-~ \t]+\r?\n)*)\r?\n)";
	static const std::regex reg(regex_str);
	std::smatch sm;
	
	if(!std::regex_search(raw_res_str, sm, reg) || sm.size() != 4) {
		throw std::runtime_error(std::string("HTTP Response Regex No Match!"));
	}
	
	return {sm[1].str(), sm[2].str(), HTTP_HEADER::parse_http_header(sm[3].str()), sm.suffix()};
}


std::string HTTP_RES::get_status_msg(const int& status_code) {
	switch(status_code){
		case 200: return "OK";
		case 400: return "Bad Request";
		case 401: return "Unauthorized";
		case 403: return "Forbidden";
		case 404: return "Not Found";
		case 500: return "Internal Server Error";
		default: throw std::runtime_error(std::string("HTTP Response Status_Code Not Found: ") + std::to_string(status_code));
	}
}

}