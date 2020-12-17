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

#include "client_utils.h"

int main(int argc, char **argv)
{

    SSL_CTX *ctx;
	SSL *ssl;
	const SSL_METHOD *meth;
	BIO *sbio;
	int err, res, ilen, sock, message_len = 0;
	char ibuf[512];
    char ubuf[512];
    char pbuf[512];
    char new_pbuf[512];
	char len_buf[25];
	char *obuf = "POST /changepw HTTP/1.0\r\n";
	char *newline = "\r\n";
	char *content_length = "Content-Length:";
	struct stat buf;

    if (argc != 6) {
        fprintf(stderr, "Usage: ./changepw <username> <password> <new_password> <CAfile> <CApath>");
        exit(1);
    }

    strncpy(ubuf, argv[1], sizeof(ubuf)-1);
    strncpy(pbuf, argv[2], sizeof(pbuf)-1);
    strncpy(new_pbuf, argv[3], sizeof(new_pbuf)-1);

	message_len += (strlen(ubuf) + strlen(pbuf) + strlen(new_pbuf));

	SSL_library_init(); /* load encryption & hash algorithms for SSL */         	
	SSL_load_error_strings(); /* load the error strings for good error reporting */

	meth = TLS_client_method();
	ctx = SSL_CTX_new(meth);

	SSL_CTX_set_default_verify_dir(ctx);
	/* SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL); */
	SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

	ssl = SSL_new(ctx);

	// This is to check the server's identity
	// res = ssl_CTX_load_verify_locations(ctx, argv[4], argv[5]);
	// if (!res) {
	// 	fprintf(stderr, "SSL error: %s\n", get_ssl_err(ssl, err));
	// 	SSL_CTX_free(ctx);
	// 	ERR_print_errors_fp(stderr);
	// 	exit(1);
	// }

	sock = get_sock(8080);
	if (sock == -1) {
		fprintf(stderr, "Could not create socket\n");
		SSL_CTX_free(ctx);
		return 1;
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

	// Open keyfile to get size
	int key_file = open(argv[4], O_RDONLY);
	if (key_file < 0) {
		perror("Failed to open keyfile");
		goto out;
	}
	fstat(key_file, &buf);
	off_t size = buf.st_size;
	message_len += size;
	sprintf(len_buf, "%d", message_len);

    /* Send request */
	// Headers
	SSL_write(ssl, obuf, strlen(obuf));
	SSL_write(ssl, content_length, strlen(content_length));
	SSL_write(ssl, len_buf, strlen(len_buf));
	SSL_write(ssl, "\r\n\r\n", strlen("\r\n\r\n"));

	// Body
    SSL_write(ssl, ubuf, strlen(ubuf));
	SSL_write(ssl, newline, strlen(newline));
    SSL_write(ssl, pbuf, strlen(pbuf));
	SSL_write(ssl, newline, strlen(newline));
    SSL_write(ssl, new_pbuf, strlen(new_pbuf));
	SSL_write(ssl, newline, strlen(newline));

	
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
	int dest = open(filename, O_CREAT | O_WRONLY, S_IRUSR | S_IWUSR); // if file already exists it will be overwritten
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
	close(sock);
	return 0;

out: 
	SSL_CTX_free(ctx);
	close(sock);
	return 1;
}