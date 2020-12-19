#include <stdio.h>
#include <strings.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>


char *get_ssl_err(SSL *ssl, int err)
{
	switch (SSL_get_error(ssl, err)) {
		case SSL_ERROR_NONE: return "SSL_ERROR_NONE";
		case SSL_ERROR_ZERO_RETURN: return "SSL_ERROR_ZERO_RETURN";
		case SSL_ERROR_WANT_READ: return "SSL_ERROR_WANT_READ";
		case SSL_ERROR_WANT_WRITE: return "SSL_ERROR_WANT_WRITE";
		case SSL_ERROR_WANT_CONNECT: return "SSL_ERROR_WANT_CONNECT";
		case SSL_ERROR_WANT_ACCEPT: return "SSL_ERROR_WANT_ACCEPT";
		case SSL_ERROR_WANT_X509_LOOKUP: return "SSL_ERROR_WANT_X509_LOOKUP";
		case SSL_ERROR_WANT_ASYNC: return "SSL_ERROR_WANT_ASYNC";
		case SSL_ERROR_WANT_ASYNC_JOB: return "SSL_ERROR_WANT_ASYNC_JOB";
		case SSL_ERROR_SYSCALL: return "SSL_ERROR_SYSCALL";
		case SSL_ERROR_SSL: return "SSL_ERROR_SSL";
	}

	return NULL;
}

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
    char new_pbuf[512];
	char *obuf = "POST /changepw HTTP/1.0\n\n";

	struct sockaddr_in sin;
	int sock;
	struct hostent *he;

    if (argc != 6) {
        fprintf(stderr, "Usage: ./changepw <username> <password> <new_password> <CAfile> <CApath>");
        exit(1);
    }

    //TODO: append newlines
    strncpy(ubuf, argv[1], sizeof(ubuf)-1);
    strncpy(pbuf, argv[2], sizeof(pbuf)-1);
    strncpy(pbuf, argv[2], sizeof(new_pbuf)-1);

	SSL_library_init(); /* load encryption & hash algorithms for SSL */         	
	SSL_load_error_strings(); /* load the error strings for good error reporting */

	meth = TLS_client_method();
	ctx = SSL_CTX_new(meth);

	SSL_CTX_set_default_verify_dir(ctx);
	/* SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL); */
	SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

	ssl = SSL_new(ctx);

	// This is to check the server's identity
	res = ssl_CTX_load_verify_locations(ctx, argv[4], argv[5]);
	if (!res) {
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
	SSL_write(ssl, obuf, strlen(obuf));

    SSL_write(ssl, ubuf, strlen(ubuf));
    SSL_write(ssl, pbuf, strlen(pbuf));
    SSL_write(ssl, pbuf, strlen(new_pbuf));
	
	int key_file = open(argv[3], O_RDONLY);
	if (key_file < 0) {
		perror("Failed to open keyfile");
		goto out;
	}
	while ((res = read(key_file, ibuf, sizeof(ibuf))) > 0) {
		SSL_write(ssl, ibuf, res);
	}
	close(key_file);


	/* Parse response */
	int response_code = get_status_code(ssl, ibuf);
	if (response_code == 403) {
		fprintf(stderr, "Messages pending. Cannot change password\n");
		goto out;
	} else if (response_code != 200) {
		fprintf(stderr, "Server error. Failed to change password\n");
		goto out;
	}

	// Read past the rest of the headers
	skip_headers(ssl);

	/* Read the certificate */

	// Create destination file
	char filename[256] = "./certificates/";
	strncat(filename, ubuf, sizeof(filename) - strlen("./certificates"));
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