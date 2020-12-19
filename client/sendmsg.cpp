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
string get_recip_certs(vector<string> recips, int message_len){
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


string encrypt(string cert, string message){
	BIO *in = NULL, *out = NULL, *tbio = NULL;
    X509 *rcert = NULL;
    STACK_OF(X509) *recips = NULL;
    CMS_ContentInfo *cms = NULL;
    string encrypted = "";
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

    if (!rcert)
        goto err;

    /* Create recipient STACK and add recipient cert to it */
    recips = sk_X509_new_null();

    if (!recips || !sk_X509_push(recips, rcert))
        goto err;

    /*
     * sk_X509_pop_free will free up recipient STACK and its contents so set
     * rcert to NULL so it isn't freed up twice.
     */
    rcert = NULL;

    /* Open content being encrypted */

    in = BIO_new(BIO_s_mem());
	BIO_puts(in, message.c_str());

    if (!in)
        goto err;

    /* encrypt content */
    cms = CMS_encrypt(recips, in, EVP_des_ede3_cbc(), flags);

    if (!cms)
        goto err;


    out = BIO_new_fp(tmp,BIO_CLOSE);
    if (!out)
        goto err;

    /* Write out S/MIME message */
    if (!SMIME_write_CMS(out, cms, in, flags)){
        goto err;
	}
	//Hacky way to read out a BIO
	rewind(tmp);
	while ((c = getc(tmp)) != EOF){
		encrypted += c;
	}


 err:

    if (encrypted == "") {
        fprintf(stderr, "Error Encrypting Data\n");
        ERR_print_errors_fp(stderr);
    }

    CMS_ContentInfo_free(cms);
    X509_free(rcert);
    sk_X509_pop_free(recips, X509_free);
    BIO_free(in);
    BIO_free(out);
    BIO_free(tbio);
    return encrypted;
}

string send_encrypted_message(string recip, string encrypted){
	SSL_CTX *ctx;
	SSL *ssl;
	const SSL_METHOD *meth;
	BIO *sbio;
	int err, res;

	int ilen;
	char ibuf[1000];
	string newline = "\n";
	char *content_length = "Content-Length:";
	string cert_req = "POST /upload HTTP/1.0\r\n";
	string end = "\r\n\r\n";
	int message_len = encrypted.length();

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
	char len_buf[25];
	SSL_write(ssl, content_length, strlen(content_length));
	message_len += recip.length() + 2;
	sprintf(len_buf, "%d", message_len);
	SSL_write(ssl, len_buf, strlen(len_buf));
	SSL_write(ssl, "\r\n\r\n", strlen("\r\n\r\n"));
	// SSL_write(ssl, "\r\n\r\n", strlen("\r\n\r\n"));
	// Body
	// TODO: Change to client cert param
	SSL_write(ssl, "@",1);
	SSL_write(ssl,recip.c_str(),recip.length());
	SSL_write(ssl, "@",1);
	SSL_write(ssl, encrypted.c_str(), encrypted.length());
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
	BIO *in = NULL, *out = NULL, *tbio = NULL;
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
	fprintf(stderr,"%s\n",cert.c_str());
    /* Read in recipient certificate */
    tbio = BIO_new(BIO_s_mem());
	BIO_puts(tbio, cert.c_str());

    if (!tbio)
        goto err;

    rcert = PEM_read_bio_X509(tbio, NULL, 0, NULL);

    BIO_reset(tbio);

    rkey = PEM_read_bio_PrivateKey(tbio, NULL, 0, NULL);

    if (!rcert)
        goto err;

    /* Open S/MIME message to decrypt */

    in = BIO_new_file("smencr.txt", "r");

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
    if (!CMS_decrypt(cms, rkey, rcert, NULL, out, 0))
        goto err;

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
	
    if (argc < 2) {
        fprintf(stderr, "Usage: ./sendmsg <recipients>\n");
        exit(1);
    }
	
	vector <string> recips;
	int content_length = 0;
	for(int i=1; i < argc; i++){
		recips.push_back(argv[i]);
		content_length += strlen(argv[i]);
		content_length += 1;
	}
	string message;
	string line;
	while(getline(cin,line)){
		message += line;
	}

	string cert_resp = get_recip_certs(recips,content_length);
	if(cert_resp.length() > 2){ // At least one valid cert
		std::stringstream ss(cert_resp);
		std::string line;
		for(string recip : recips){
			string cert;
			while (std::getline(ss, line)) {
				if(line == ".\n"){
					fprintf(stderr,"%s\n did not have a valid cert", recip.c_str());
				} else if (line == "-----END CERTIFICATE-----"){
					cert += line;
					cert.push_back('\n');
					break;
				} else{
					cert += line;
					cert.push_back('\n');
				}
			}
			//Encrypt to Certificate and sign
			string encrypted = encrypt(cert,message);
			fprintf(stderr,"%s's cert: %s\n",recip.c_str(),encrypted.c_str());
			// Send Request (Note if we want all to fail on one failure, then we do outside)
			string resp = send_encrypted_message(recip, encrypted);
			decrypt(cert,encrypted);
		}
	}


}