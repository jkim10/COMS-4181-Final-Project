#include <iostream>
#include <string>
#include <bits/stdc++.h> 
#include "utils.h"
extern "C"
{
	#include "client_utils.h"
}
using namespace std;
// Change to return vector of certificates
int get_recip_certs(vector<string> recips, int message_len){
	SSL_CTX *ctx;
	SSL *ssl;
	const SSL_METHOD *meth;
	BIO *sbio;
	int err, res;

	int ilen;
	char ibuf[1000];
	string newline = "\n";
	char *content_length = "Content-Length:";
	string cert_req = "POST /sendmsg HTTP/1.0\r\n";
	string end = "\r\n\r\n";

	struct sockaddr_in sin;
	int sock;
	struct hostent *he;

	SSL_library_init(); /* load encryption & hash algorithms for SSL */         	
	SSL_load_error_strings(); /* load the error strings for good error reporting */

	meth = TLS_client_method();
	ctx = SSL_CTX_new(meth);

	SSL_CTX_set_default_verify_dir(ctx);
	/* SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL); */
	SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

	ssl = SSL_new(ctx);

	sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sock < 0) {
		perror("socket");
		SSL_CTX_free(ctx);
		return 1;
	}

	bzero(&sin, sizeof sin);
	sin.sin_family = AF_INET;
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
	SSL_write(ssl, cert_req.c_str(), cert_req.length());
	char len_buf[25];
	SSL_write(ssl, content_length, strlen(content_length));
	string cert = ReadFiletoString("./duckduckgo.pem");
	message_len += cert.length();
	sprintf(len_buf, "%d", message_len);
	SSL_write(ssl, len_buf, strlen(len_buf));
	SSL_write(ssl, "\r\n\r\n", strlen("\r\n\r\n"));
	// SSL_write(ssl, "\r\n\r\n", strlen("\r\n\r\n"));
	// Body
	// TODO: Change to client cert param
	SSL_write(ssl, cert.c_str(), cert.length());
	for (string x : recips) {
		SSL_write(ssl, x.c_str(), x.length());
	    SSL_write(ssl, newline.c_str(), newline.length());
	}
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


int main(int argc, char **argv)
{
	
    if (argc < 2) {
        fprintf(stderr, "Usage: ./sendmsg <recipients>\n");
        exit(1);
    }
	
	vector <string> recips;
	int message_len = 0;
	for(int i=1; i < argc; i++){
		recips.push_back(argv[i]);
		message_len += strlen(argv[i]);
		message_len += 1;
	}
	get_recip_certs(recips,message_len);

	vector <string> certs;
}