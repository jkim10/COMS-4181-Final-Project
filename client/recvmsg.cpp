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


string get_encrypted_message(string cert){
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
		SSL_free(ssl);
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
	int message_len = 0;
	message_len += cert.length();

	SSL_write(ssl, to_string(message_len).c_str(), to_string(message_len).length());
	SSL_write(ssl, "\r\n\r\n", strlen("\r\n\r\n"));

	// Body
	SSL_write(ssl, cert.c_str(), cert.length());

	int response_code = get_status_code(ssl, ibuf);
	if (response_code != 200) {
		fprintf(stderr, "Failed with code=%d\n", response_code);
		goto out;
	}
		

	// Read past the rest of the headers
	skip_headers(ssl);
	string body = "";
	while ((ilen = SSL_read(ssl, ibuf, sizeof ibuf - 1)) > 0) {
		ibuf[ilen] = '\0';
		body += ibuf;
	}

	SSL_CTX_free(ctx);
	SSL_free(ssl);
	return body;
	}


out:
	SSL_CTX_free(ctx);
	SSL_free(ssl);
	close(sock);
	return "";		
}

string decrypt(string cert, string pkey_path, string message){
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

	key = BIO_new_file(pkey_path.c_str(), "r");
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

string verify(string message, string sender_cert){
	BIO *in = NULL, *out = NULL, *tbio = NULL, *cont = NULL, *sender = NULL, *inter = NULL;
    X509_STORE *st = NULL;
    X509 *cacert = NULL;
	X509 *scert = NULL;
	X509 *intercert = NULL;
	STACK_OF(X509) *sk;
    CMS_ContentInfo *cms = NULL;
	FILE* tmp = tmpfile();
	string verified = "";
	int c;

    int ret = 1;

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

	int flags = CMS_NOINTERN;

    /* Set up trusted CA certificate store */

    st = X509_STORE_new();

    /* Read in CA certificate */
    tbio = BIO_new_file("ca.cert.pem", "r");

    if (!tbio)
        goto err;

    cacert = PEM_read_bio_X509(tbio, NULL, 0, NULL);

    if (!cacert)
        goto err;

    if (!X509_STORE_add_cert(st, cacert))
        goto err;

    /* Open message being verified */

    in = BIO_new(BIO_s_mem());
	BIO_puts(in, message.c_str());

    if (!in)
        goto err;

    /* parse message */
    cms = SMIME_read_CMS(in, &cont);

    if (!cms)
        goto err;

    /* File to output verified content to */
    out = BIO_new_fp(tmp,BIO_CLOSE);
    if (!out)
        goto err;

	sender = BIO_new(BIO_s_mem());
	BIO_puts(sender, sender_cert.c_str());

	scert = PEM_read_bio_X509(sender, NULL, 0, NULL);

	sk = sk_X509_new_null();

	if (sk_X509_push(sk, scert) == 0)
		goto err;

	if (!X509_STORE_add_cert(st, scert))
        goto err;

	inter = BIO_new_file("intermediate.cert.pem", "r");
	intercert = PEM_read_bio_X509(inter,NULL,0,NULL);
	if (!X509_STORE_add_cert(st, intercert))
        goto err;

    if (!CMS_verify(cms, sk, st, cont, out, flags)) {
        fprintf(stderr, "Verification Failure\n");
        goto err;
    }

    fprintf(stderr, "Verification Successful\n");

    //Hacky way to read out a BIO
	rewind(tmp);
	while ((c = getc(tmp)) != EOF){
		verified += c;
	}

 err:

    if (verified == "") {
        fprintf(stderr, "Error Verifying Data\n");
        ERR_print_errors_fp(stderr);
    }

    CMS_ContentInfo_free(cms);
    X509_free(cacert);
	X509_free(scert);
	X509_free(intercert);
    BIO_free(in);
    BIO_free(out);
    BIO_free(tbio);
	BIO_free(cont);
	BIO_free(sender);
	BIO_free(inter);
    return verified;
}

bool matchCertPkey(string cert, string pKey){
    /*
     * On OpenSSL 1.0.0 and later only:
     * for streaming set CMS_STREAM
     */
	int isMatch = 1;
	int rc;
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    /* Read in recipient certificate */
    BIO *cert_bio = BIO_new(BIO_s_mem());
	BIO_puts(cert_bio, cert.c_str());



    X509 *rcert = PEM_read_bio_X509(cert_bio, NULL, 0, NULL);

	BIO *key = BIO_new(BIO_s_mem());
	BIO_puts(key, pKey.c_str());
    EVP_PKEY* pkey = PEM_read_bio_PrivateKey(key, NULL, 0, NULL);

	if (!cert_bio || !key || !pkey)
        goto err;

	rc = X509_check_private_key(rcert,pkey);
	if(rc == 0){
		long err = ERR_get_error();
		char err_buf[1000];
		fprintf(stderr, "Private key did not match. Error Code: \n%d\n", EVP_PKEY_size(pkey));
		isMatch = 0;
	}

    

err:
    X509_free(rcert);
    BIO_free(cert_bio);
    BIO_free(key);
	EVP_PKEY_free(pkey);
    return isMatch;
}

int main(int argc, char **argv)
{
	
    if (argc != 3) {
        fprintf(stderr, "Usage: ./recv <path/to/cert> <path/to/key>\n");
        exit(1);
    }
	
	string message;
	string line;
	string cert_path = argv[1];
	string pkey_path = argv[2];
	string cert = ReadFiletoString(cert_path.c_str());

	string resp = get_encrypted_message(cert);
	string sender_cert = ParseSenderCert(resp);
	string signed_message = ParseRMMessage(resp);
	if(signed_message.length() == 0 || resp == ""){
		fprintf(stderr, "No valid messages\n");
		exit(1);
	}
	string encrypted_message = verify(signed_message,sender_cert);
	if(encrypted_message.length() == 0) {exit(1);}
	string decrypted = decrypt(cert, pkey_path, encrypted_message);
	// string decrypted = decrypt(cert, pkey_path, signed_message);
	if(decrypted.length()==0){
		fprintf(stderr,"Could not decrypt. Exiting.\n");
		exit(1);
	}
	fprintf(stderr,"============\nMessage\n============\n%s\n",decrypted.c_str());

}