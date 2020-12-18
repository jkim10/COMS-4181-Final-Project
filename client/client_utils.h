#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdio.h>
#include <strings.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#define SSL_ERROR -1
#define BAD_RESPONSE -2

char *get_ssl_err(SSL *ssl, int err);
int get_status_code(SSL *ssl, char *ibuf);
void skip_headers(SSL *ssl);
int get_sock(int port);