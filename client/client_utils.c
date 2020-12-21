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

int get_sock(int port)
{
	int sock;
	struct sockaddr_in sin;
	struct hostent *he;

	sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sock < 0) {
		perror("socket");
		return -1;
	}

	bzero(&sin, sizeof sin);
	sin.sin_family = AF_INET;
	sin.sin_port = htons(port);

	he = gethostbyname("localhost");
	memcpy(&sin.sin_addr, (struct in_addr *)he->h_addr, he->h_length);
	if (connect(sock, (struct sockaddr *)&sin, sizeof sin) < 0) {
		perror("connect");
		return -1;
	}

	return sock;
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
	code[3] = 0;
	
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

int is_printable(char *str)
{
	for (int i = 0; i < strlen(str); i++) {
		if (str[i] < 32 || str[i] > 126)
			return 0;
	}
	return 1;
}

int get_inputs(char username[], char password[], char new_password[], char key[])
{
	char *pass, *new_pass;
	int i = 0;

	fprintf(stderr, "Username: ");
	for (i = 0; i <= MAX_CLIENT_INPUT; i++) {
		if (i == MAX_CLIENT_INPUT)
			return 0;
		read(STDIN_FILENO, username+i, 1);
		if (username[i] == '\n') {
			username[i] = 0;
			break;
		}
	}
	if (username[i] != 0)
		return 0;

	pass = getpass("Password: ");
	if (strlen(pass) > MAX_CLIENT_INPUT) {
		free(pass);
		pass = NULL;
		return 0;
	}
	strncpy(password, pass, MAX_CLIENT_INPUT);

	if (new_password != NULL) {
		new_pass = getpass("New password: ");
		if (strlen(new_pass) > MAX_CLIENT_INPUT) {
			free(new_pass);
			new_pass = NULL;
			return 0;
		}
		strncpy(new_password, new_pass, MAX_CLIENT_INPUT);
	}

	fprintf(stderr, "Path to private key: ");
	for (i = 0; i <= MAX_CLIENT_INPUT; i++) {
		if (i == MAX_CLIENT_INPUT)
			return 0;
		read(STDIN_FILENO, key+i, 1);
		if (key[i] == '\n') {
			key[i] = 0;
			break;
		}
	}
	if (key[i] != 0)
		return 0;
	
	free(pass);
	pass = NULL;

	return 1;
}