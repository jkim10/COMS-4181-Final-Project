#include <memory>
#include <signal.h>
#include <stdexcept>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <unistd.h>
#include <vector>

#include "ssl_common.h"
#include "http_common.h"
#include "req_res.h"

namespace my {

std::vector<std::string> split_headers(const std::string& text)
{
	std::vector<std::string> lines;
	const char *start = text.c_str();
	while (const char *end = strstr(start, "\r\n")) {
		lines.push_back(std::string(start, end));
		start = end + 2;
	}
	return lines;
}

HTTP_REQ receive_http_message(BIO *bio)
{
	std::string headers = my::receive_some_data(bio);
	char *end_of_headers = strstr(&headers[0], "\r\n\r\n");
	while (end_of_headers == nullptr) {
		headers += my::receive_some_data(bio);
		end_of_headers = strstr(&headers[0], "\r\n\r\n");
	}
	std::string body = std::string(end_of_headers+4, &headers[headers.size()]);
	headers.resize(end_of_headers+2 - &headers[0]);
	size_t content_length = 0;
	for (const std::string& line : my::split_headers(headers)) {
		if (const char *colon = strchr(line.c_str(), ':')) {
			auto header_name = std::string(&line[0], colon);
			if (header_name == "Content-Length") {
				content_length = std::stoul(colon+1);
			}
		}
	}
	while (body.size() < content_length) {
		body += my::receive_some_data(bio);
	}
	try {
		return HTTP_REQ(headers + "\r\n" + body);
	} catch (const std::exception& ex) {
		fprintf(stderr, "%s\n", ex.what());
		//fprintf(stderr, "%s\n", headers.c_str());
		send_errors_and_throw(bio, 400, "request not understood!");
	}
}

void send_http_response(BIO *bio, int status_code, const std::string& msg)
{
	const HTTP_RES res(status_code, msg);
	std::string str_res = res.str();

	BIO_write(bio, str_res.data(), str_res.size());
	BIO_flush(bio);
}

[[noreturn]] void send_errors_and_throw(BIO *bio, int status_code, const std::string& msg)
{
    send_http_response(bio, status_code, msg);
    throw std::runtime_error(std::string(msg) + "\n");
}

my::UniquePtr<BIO> accept_new_tcp_connection(BIO *accept_bio)
{
	if (BIO_do_accept(accept_bio) <= 0) {
		return nullptr;
	}
	return my::UniquePtr<BIO>(BIO_pop(accept_bio));
}

PASS_AUTH_REQ pass_auth(BIO *bio, const std::string& req_str) {
	const my::PASS_AUTH_REQ auth_req(req_str);
	try {
		if (!auth_req.verify()) {
			my::send_errors_and_throw(bio, 401, "incorrect username/password!");
		}
	} catch (const std::system_error& ex) {
		my::send_errors_and_throw(bio, 500, "password verification error!\n");
	}
	return auth_req;
}

void getcert(BIO *bio, const std::string& req_str) {
	const PASS_AUTH_REQ auth_req = my::pass_auth(bio, req_str);
	
	// TODO: retrive and send cert
	std::cout << "getcert: \n" << auth_req.str();
	
	my::send_http_response(bio, 200, "CERTIFICATE");
}

void changepw(BIO *bio, const std::string& req_str) {
	const PASS_AUTH_REQ auth_req = my::pass_auth(bio, req_str);
	
	// TODO: change pwd
	std::cout << "changepw: \n" << auth_req.str();
	
	my::send_http_response(bio, 200, "");
}

} // namespace my

int main()
{
#if OPENSSL_VERSION_NUMBER < 0x10100000L
	SSL_library_init();
	SSL_load_error_strings();
	auto ctx = my::UniquePtr<SSL_CTX>(SSL_CTX_new(SSLv23_method()));
#else
	auto ctx = my::UniquePtr<SSL_CTX>(SSL_CTX_new(TLS_method()));
	SSL_CTX_set_min_proto_version(ctx.get(), TLS1_2_VERSION);
#endif

	if (SSL_CTX_use_certificate_file(ctx.get(), "server-certificate.pem", SSL_FILETYPE_PEM) <= 0) {
		my::print_errors_and_exit("Error loading server certificate");
	}
	if (SSL_CTX_use_PrivateKey_file(ctx.get(), "server-private-key.pem", SSL_FILETYPE_PEM) <= 0) {
		my::print_errors_and_exit("Error loading server private key");
	}

	auto accept_bio = my::UniquePtr<BIO>(BIO_new_accept("8080"));
	if (BIO_do_accept(accept_bio.get()) <= 0) {
		my::print_errors_and_exit("Error in BIO_do_accept (binding to port 8080)");
	}

	static auto shutdown_the_socket = [fd = BIO_get_fd(accept_bio.get(), nullptr)]() {
		close(fd);
	};
	signal(SIGINT, [](int) { shutdown_the_socket(); });

	while (auto bio = my::accept_new_tcp_connection(accept_bio.get())) {
		bio = std::move(bio)
			| my::UniquePtr<BIO>(BIO_new_ssl(ctx.get(), 0))
			;
		try {
			fprintf(stderr, "\n----------\nGot request: ");
			my::HTTP_REQ request = my::receive_http_message(bio.get());
			
			//fprintf(stderr, "%s\n", request.str().c_str());
			fprintf(stderr, "/%s\n", request.endpoint.c_str());
			
			if (request.method == "POST" && request.endpoint == "getcert") {
				my::getcert(bio.get(), request.body);
			} else if (request.method == "POST" && request.endpoint == "changepw") {
				my::changepw(bio.get(), request.body);
			} else if (request.endpoint == "sendmsg") {
				// TODO: sendmsg
			} else if (request.endpoint == "recvmsg") {
				// TODO: recvmsg
			} else {
				my::send_errors_and_throw(bio.get(), 400, "Request Method/Endpoint Not Found!");
			}
			
			//my::send_http_response(bio.get(), 200, "okay cool\n");
		} catch (const std::exception& ex) {
			fprintf(stderr, "Worker exited with exception:\n%s\n", ex.what());
		}
	}
	fprintf(stderr, "\nClean exit!\n");
}