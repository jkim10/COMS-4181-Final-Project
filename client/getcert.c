#include "client_utils.h"

int main(int argc, char **argv)
{

    SSL_CTX *ctx;
	SSL *ssl;
	const SSL_METHOD *meth;
	BIO *sbio;
	int err, res, sock, ilen, status, message_len = 0;

	char ibuf[512], ubuf[512], pbuf[512];
	char *newline = "\r\n";
	char len_buf[25];
	char *content_length = "Content-Length:";
	char *obuf = "POST /getcert HTTP/1.0\r\n";
	char csr_dest[256] = "./certificates/csr/";
	struct stat buf;

    if (argc != 4) {
        fprintf(stderr, "Usage: ./getcert <username> <password> <path-to-private-key>\n");
        exit(1);
    }

	//TODO: use getpass()

	//TODO: check if username or password contain a newline. this is illegal

    strncpy(ubuf, argv[1], sizeof(ubuf)-1);
	strncpy(pbuf, argv[2], sizeof(pbuf)-1);
	message_len += (strlen(ubuf) + strlen(pbuf));
	
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

	/* Call getcert-client.sh */
	// Set up dest filename
	strncat(csr_dest, argv[1], sizeof(csr_dest) - strlen(csr_dest));
	strcat(csr_dest, ".csr.pem");
	printf("dest=%s\n", csr_dest);
	int pid = fork();
	if (pid < 0) {
		perror("fork failed");
		goto out;
	} else if (pid == 0) { // child
		// ./getcert-client.sh <path_to_private_key> <csr_dest> <username>
		// ./getcert-client.sh argv[3] <dest> argv[1]
		execl("/bin/sh", "sh", "../cert_gen/getcert-client.sh", argv[3], csr_dest, 
			argv[1], (char *) NULL);
		printf("execl failed\n");
	} else { // parent
		waitpid(pid, &status, 0); // TODO: check return val
		if(WEXITSTATUS(status) == 1)
			goto out;
		
	}

	// Open csr
	int csr = open(csr_dest, O_RDONLY);
	if (csr < 0) {
		perror("Failed to open CSR file");
		goto out;
	}
	// Stat csr
	fstat(csr, &buf);
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

	// Send CSR
	while ((res = read(csr, ibuf, sizeof(ibuf))) > 0) {
		SSL_write(ssl, ibuf, res);
	}
	close(csr);

	// End of request

	/* Parse response */
	int response_code = get_status_code(ssl, ibuf);
	if (response_code == BAD_RESPONSE)
		printf("bad response, code = %d\n", response_code);
	else if (response_code == SSL_ERROR)
		printf("SSL error, response code = %d\n", response_code);
	if (response_code != 200)
		goto out;

	// Read past the rest of the headers
	skip_headers(ssl);

	/* Read the certificate */

	// Create destination file
	char filename[256] = "./certificates/";
	strncat(filename, ubuf, sizeof(filename) - strlen("./certificates"));
	strcat(filename, ".cert.pem");
	int dest = open(filename, O_CREAT | O_WRONLY, S_IRUSR | S_IWUSR); // if file already exists it will be overwritten
	printf("dest=%d\n", dest);
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