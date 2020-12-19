#include <iostream>
#include <sstream>
#include <string>
#include <bits/stdc++.h> 
#include "utils.h"
#include <filesystem>


#include <openssl/pem.h>
#include <openssl/cms.h>
#include <openssl/err.h>
#include <openssl/bio.h>
extern "C"
{
	#include "client_utils.h"
}
using namespace std;


string get_encrypted_message(string recip, string cert){
	SSL_CTX *ctx;
	SSL *ssl;
	const SSL_METHOD *meth;
	BIO *sbio;
	int err, res;

	int ilen;
	char ibuf[1000];
	string newline = "\n";
	string content_length = "Content-Length:";
	string cert_req = "POST /recvmsg HTTP/1.0\r\n";
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
		return "";
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
	SSL_write(ssl, content_length.c_str(), content_length.length());
	// TODO: when we have certificates setup, uncomment this and replace duckduckgo
	int message_len = 0;
	message_len += cert.length() + recip.length() + 2;
	SSL_write(ssl, to_string(message_len).c_str(), to_string(message_len).length());
	SSL_write(ssl, "\r\n\r\n", strlen("\r\n\r\n"));
	// SSL_write(ssl, "\r\n\r\n", strlen("\r\n\r\n"));
	// Body
	SSL_write(ssl, "@",1);
	SSL_write(ssl,recip.c_str(),recip.length());
	SSL_write(ssl, "@",1);
	SSL_write(ssl, cert.c_str(), cert.length());

	int response_code = get_status_code(ssl, ibuf);
	printf("response code = %d\n", response_code);
	// there are more specific values if we want to return nicer error messages...
	if (response_code != 200)
		goto out;

	// Read past the rest of the headers
	skip_headers(ssl);
	string body = "";
	while ((ilen = SSL_read(ssl, ibuf, sizeof ibuf - 1)) > 0) {
		ibuf[ilen] = '\0';
		body += ibuf;
	}

	SSL_CTX_free(ctx);
	return body;
	}


out:
	SSL_CTX_free(ctx);
	close(sock);
	return "";		
}

string decrypt(string cert, string message){
	BIO *in = NULL, *out = NULL, *tbio = NULL, *key = NULL;
    X509 *rcert = NULL;
    EVP_PKEY *rkey = NULL;
    CMS_ContentInfo *cms = NULL;
    string decrypted = "";
	FILE* tmp = tmpfile();
	int c;

    /*
     * On OpenSSL 1.0.0 and later only:
     * for streaming set CMS_STREAM
     */
    int flags = CMS_STREAM;

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    /* Read in recipient certificate */
    tbio = BIO_new(BIO_s_mem());
	BIO_puts(tbio, cert.c_str());

    if (!tbio)
        goto err;

    rcert = PEM_read_bio_X509(tbio, NULL, 0, NULL);

    BIO_reset(tbio);

	key = BIO_new_file("duckduckgo-private-key.pem","r");
    rkey = PEM_read_bio_PrivateKey(key, NULL, 0, NULL);

    if (!rcert || !rkey)
        goto err;

    /* Open S/MIME message to decrypt */
    in = BIO_new(BIO_s_mem());
	BIO_puts(in, message.c_str());

    if (!in)
        goto err;

    /* Parse message */
    cms = SMIME_read_CMS(in, NULL);

    if (!cms)
        goto err;

    out = BIO_new_fp(tmp,BIO_CLOSE);
    if (!out)
        goto err;

    /* Decrypt S/MIME message */
    if (!CMS_decrypt(cms, rkey, rcert, NULL, out, 0)){
		fprintf(stderr,"error code: %d\n", ERR_get_error());
	    goto err;
	}
	


	//Hacky way to read out a BIO
	rewind(tmp);
	while ((c = getc(tmp)) != EOF){
		decrypted += c;
	}


 err:

    if (decrypted == "") {
        fprintf(stderr, "Error Decrypting Data\n");
        ERR_print_errors_fp(stderr);
    }

    CMS_ContentInfo_free(cms);
    X509_free(rcert);
    EVP_PKEY_free(rkey);
    BIO_free(in);
    BIO_free(out);
    BIO_free(tbio);
    return decrypted;
}



int main(int argc, char **argv)
{
	
    if (argc < 3) {
        fprintf(stderr, "Usage: ./recv recip <path/to/cert>\n");
        exit(1);
    }
	
	string message;
	string line;
	string recip = argv[1];
	string cert_path = argv[2];
	string cert = ReadFiletoString(cert_path.c_str());

	string encrypted_message = get_encrypted_message(recip,cert);
	string decrypted = decrypt(cert, encrypted_message);
	fprintf(stderr,"%s\n",decrypted.c_str());

}