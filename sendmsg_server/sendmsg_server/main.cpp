#include "utils.h"

int main()
{
	string client_cert_path, client_cert, recipient, encrypt_cert;

	cout << "Enter client cert name (use client.cert.pem for testing): ";
	cin >> client_cert_path;
	cout << "Enter recipient name (only addleness contains a valid cert for now): ";
	cin >> recipient;

	client_cert = ReadFiletoString(client_cert_path.c_str());

	if (VerifyCert(client_cert))
	{
		encrypt_cert = GetCert(recipient);
		WriteStringtoFile(encrypt_cert, "./encrypt.cert.pem");
	}

	//RemoveCert("./tmp/client.cert.pem");

	return 0;
}