#include "http_common.h"

using namespace my;

int main() {
	HTTP_REQ req ("GET /getcert HTTP/1.0\nContent-length: 1\nContent-Length:2\nContent-Length: 3\n\r\nusername\npassword\n--BEGIN PUBKEY--\n...\n--END PUBKEY--\n"s);
	std::cerr << req.method << "\n";
	std::cerr << req.endpoint << "\n";
	//std::cerr << req.header << "\n";
	for (auto& header: req.headers) {
		std::cerr << header.name << " :: " << header.value << "\n";
	}
	//std::cerr << req.body << "\n";
	std::cerr << "\n";
	
	
	HTTP_RES res ("HTTP/1.1 301 Moved Permanently\nContent-length:  1\ndate: Wed, 16 Dec 2020 16:55:02 GMT\nserver: Apache/2.4.29 (Ubuntu)\n\r\nusername\npassword\n--BEGIN PUBKEY--\n...\n--END PUBKEY--\n"s);
	std::cerr << res.status_code << "\n";
	std::cerr << res.status_msg << "\n";
	//std::cerr << res.header << "\n";
	for (auto& header: res.headers) {
		std::cerr << header.name << " :: " << header.value << "\n";
	}
	//std::cerr << res.body << "\n";
	std::cerr << "\n";
	
	
	auto headers = HTTP_HEADER::parse_http_header("Content-length:  1 \ndate: Wed, 16 Dec 2020 16:55:02 GMT\nserver: Apache/2.4.29 (Ubuntu)\n"s);
	std::cerr << "Headers: " << "\n";
	for (auto& header: headers) {
		std::cerr << header.name << " :: " << header.value << "\n";
	}
	std::cerr << "\n";
}