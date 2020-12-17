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

std::string receive_some_data(BIO *bio)
{
	char buffer[1024];
	int len = BIO_read(bio, buffer, sizeof(buffer));
	if (len < 0) {
		my::print_errors_and_throw("error in BIO_read");
	} else if (len > 0) {
		return std::string(buffer, len);
	} else if (BIO_should_retry(bio)) {
		return receive_some_data(bio);
	} else {
		my::print_errors_and_throw("empty BIO_read");
	}
}

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
	return HTTP_REQ(headers + "\r\n" + body);
}

void send_http_response(BIO *bio, const std::string& body)
{
	std::string response = "HTTP/1.1 200 OK\r\n";
	response += "Content-Length: " + std::to_string(body.size()) + "\r\n";
	response += "\r\n";

	BIO_write(bio, response.data(), response.size());
	BIO_write(bio, body.data(), body.size());
	BIO_flush(bio);
}

my::UniquePtr<BIO> accept_new_tcp_connection(BIO *accept_bio)
{
	if (BIO_do_accept(accept_bio) <= 0) {
		return nullptr;
	}
	return my::UniquePtr<BIO>(BIO_pop(accept_bio));
}

void getcert(const PASS_AUTH_REQ auth_req) {
	// TODO: retrive and send cert
	std::cout << "getcert: \n" << auth_req.str();
}

void changepw(const PASS_AUTH_REQ auth_req) {
	// TODO: change pwd
	std::cout << "changepw: \n" << auth_req.str();
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
			my::HTTP_REQ request = my::receive_http_message(bio.get());
			printf("Got request:\n");
			printf("%s\n", request.str().c_str());
			
			if (request.method == "POST" && (request.endpoint == "getcert" || request.endpoint == "changepw")) {
				my::PASS_AUTH_REQ auth_req(request.body);
				if (!auth_req.verify()) {
					my::send_http_response(bio.get(), "incorrect password!\n");
					my::print_errors_and_throw("incorrect password!");
				}
				if (request.endpoint == "getcert") {
					my::getcert(auth_req);
				} else if (request.endpoint == "changepw") {
					my::changepw(auth_req);
				} else {
					my::print_errors_and_throw("code not supposed to reach here...");
				}
			} else if (request.method == "POST" && request.endpoint == "changepw") {
				
			} else {
				std::cerr << "Request Method/Endpoint Not Found!\n";
			}
			
			my::send_http_response(bio.get(), "okay cool\n");
		} catch (const std::exception& ex) {
			printf("Worker exited with exception:\n%s\n", ex.what());
		}
	}
	printf("\nClean exit!\n");
}