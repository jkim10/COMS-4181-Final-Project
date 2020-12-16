#include <iostream>
#include <string>
extern "C"
{
	#include "client_utils.h"
}
using namespace std;
int main(int argc, char **argv)
{

    SSL_CTX *ctx;
	SSL *ssl;
	const SSL_METHOD *meth;
	BIO *sbio;
	int err, res;

	int ilen;
	char ibuf[1000];
	string newline = "\n";
	string content_length= "Content-Length:";
	int u_len, p_len;
	string obuf = "GET / HTTP/1.1\r\n\r\n";

	struct sockaddr_in sin;
	int sock;
	struct hostent *he;

    if (argc < 2) {
        fprintf(stderr, "Usage: ./sendmsg <recipients>\n");
        exit(1);
    }


	//TODO: check if username or password contain a newline. this is illegal

	
	SSL_library_init(); /* load encryption & hash algorithms for SSL */         	
	SSL_load_error_strings(); /* load the error strings for good error reporting */

	meth = TLS_client_method();
	ctx = SSL_CTX_new(meth);

	SSL_CTX_set_default_verify_dir(ctx);
	/* SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL); */
	SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

	ssl = SSL_new(ctx);

	// This is to check the server's identity
	err = ssl_CTX_load_verify_locations(ctx, argv[4], argv[5]);
	if (!err) {
		fprintf(stderr, "SSL error: %s\n", get_ssl_err(ssl, err));
		SSL_CTX_free(ctx);
		ERR_print_errors_fp(stderr);
		exit(1);
	}

	sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sock < 0) {
		perror("socket");
		SSL_CTX_free(ctx);
		return 1;
	}

	bzero(&sin, sizeof sin);
	sin.sin_family = AF_INET;
	//sin.sin_port = htons(443);
	sin.sin_port = htons(8080);

	he = gethostbyname("localhost");
	memcpy(&sin.sin_addr, (struct in_addr *)he->h_addr, he->h_length);
	if (connect(sock, (struct sockaddr *)&sin, sizeof sin) < 0) {
		perror("connect");
		goto out;
	}

	{
	sbio=BIO_new(BIO_s_socket());
	BIO_set_fd(sbio, sock, BIO_NOCLOSE);
	SSL_set_bio(ssl, sbio, sbio);

	err = SSL_connect(ssl);
	if (SSL_connect(ssl) != 1) {
		fprintf(stderr, "SSL error: %s\n", get_ssl_err(ssl, err));
		ERR_print_errors_fp(stderr);
		goto out;
	}

    /* Send request */
	// Headers
	SSL_write(ssl, obuf.c_str(), obuf.length());
	// SSL_write(ssl, "\r\n\r\n", strlen("\r\n\r\n"));
	
	int response_code = get_status_code(ssl, ibuf);
	printf("response code = %d\n", response_code);
	// there are more specific values if we want to return nicer error messages...
	if (response_code != 200)
		goto out;

	// Read past the rest of the headers
	skip_headers(ssl);
	while ((ilen = SSL_read(ssl, ibuf, sizeof ibuf - 1)) > 0) {
		ibuf[ilen] = '\0';
		printf("%s", ibuf);
	}

	SSL_CTX_free(ctx);
	return 0;
	}


out:
	SSL_CTX_free(ctx);
	close(sock);
	return 1;		
	
}