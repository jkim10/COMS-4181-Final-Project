#include "client_utils.h"

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

int get_status_code(SSL *ssl, char *ibuf)
{
    int err;
    char code[4];

    err = SSL_read(ssl, ibuf, strlen("HTTP/1.0 200 OK\n"));
    if (err <= 0) {
		// read failed
		fprintf(stderr, "SSL error: %s\n", get_ssl_err(ssl, err));
		ERR_print_errors_fp(stderr);
		return SSL_ERROR;
    } else if (err < strlen("HTTP/1.0 200 OK\n")) {
        return BAD_RESPONSE;
    }

    strncpy(code, ibuf + strlen("HTTP/1.0 "), 3);
    printf("code = %s\n", code);

    return atoi(code);

}

void skip_headers(SSL *ssl)
{
    char curr, prev = 0;
	while (SSL_read(ssl, &curr, 1) > 0) {
		if (curr == '\r')
			continue;
		if (curr == '\n' && prev == '\n')
			break;
		
		prev = curr;
	}
}