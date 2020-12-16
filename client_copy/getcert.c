#include "client_utils.h"

int main(int argc, char **argv)
{

    SSL_CTX *ctx;
	SSL *ssl;
	const SSL_METHOD *meth;
	BIO *sbio;
	int err, res;

	int ilen;
	char ibuf[512];
    char ubuf[512];
    char pbuf[512];
	char *newline = "\n";
	char *content_length = "Content-Length:";
	int u_len, p_len;
	char *obuf = "GET /getcert HTTP/1.0\n";

	struct sockaddr_in sin;
	int sock;
	struct hostent *he;

    if (argc != 4) {
        fprintf(stderr, "Usage: ./getcert <username> <password> <path-to-public-key>\n");
        exit(1);
    }

	//TODO: use getpass()

	//TODO: check if username or password contain a newline. this is illegal

    strncpy(ubuf, argv[1], sizeof(ubuf)-2);
	u_len = strlen(ubuf) + 1;
	ubuf[u_len - 1] = '\n';
    strncpy(pbuf, argv[2], sizeof(pbuf)-2);
	p_len = strlen(pbuf) + 1;
	pbuf[p_len - 1] = '\n';
	
	SSL_library_init(); /* load encryption & hash algorithms for SSL */         	
	SSL_load_error_strings(); /* load the error strings for good error reporting */

	meth = TLS_client_method();
	ctx = SSL_CTX_new(meth);

	SSL_CTX_set_default_verify_dir(ctx);
	/* SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL); */
	SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

	ssl = SSL_new(ctx);

	// This is to check the server's identity
	//err = ssl_CTX_load_verify_locations(ctx, argv[4], argv[5]);
	// if (!err) {
	// 	fprintf(stderr, "SSL error: %s\n", get_ssl_err(ssl, err));
	// 	SSL_CTX_free(ctx);
	// 	ERR_print_errors_fp(stderr);
	// 	exit(1);
	// }

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
	SSL_write(ssl, obuf, strlen(obuf));
	SSL_write(ssl, content_length, strlen(content_length));
	SSL_write(ssl, "100", strlen("100"));
	SSL_write(ssl, "\r\n\r\n", strlen("\r\n\r\n"));

	// Body
    SSL_write(ssl, ubuf, u_len);
	SSL_write(ssl, newline, strlen(newline));
    SSL_write(ssl, pbuf, p_len);
	SSL_write(ssl, newline, strlen(newline));
	
	int key_file = open(argv[3], O_RDONLY);
	if (key_file < 0) {
		perror("Failed to open keyfile");
		goto out;
	}
	while ((res = read(key_file, ibuf, sizeof(ibuf))) > 0) {
		SSL_write(ssl, ibuf, res);
	}
	close(key_file);

	// End of request

	/* Parse response */
	int response_code = get_status_code(ssl, ibuf);
	printf("response code = %d\n", response_code);
	// there are more specific values if we want to return nicer error messages...
	if (response_code != 200)
		goto out;

	// Read past the rest of the headers
	skip_headers(ssl);

	/* Read the certificate */

	// Create destination file
	char filename[256] = "./certificates/";
	strncat(filename, ubuf, sizeof(filename) - strlen("./certificates"));
	//printf("filename=%s\n", filename);
	int dest = open(filename, O_CREAT | O_WRONLY); // if file already exists it will be overwritten
	if (dest < 0 ){
		perror("Failed to create certificate file");
		goto out;
	}

	// Write to file
	while ((ilen = SSL_read(ssl, ibuf, sizeof(ibuf) - 1)) > 0) {
		res = write(dest, ibuf, ilen);
		if (res < ilen) {
			perror("Write to certificate file failed");
			close(dest);
			goto out;
		}
	}

	close(dest);
	SSL_CTX_free(ctx);
	return 0;


out:
	SSL_CTX_free(ctx);
	close(sock);
	return 1;
}