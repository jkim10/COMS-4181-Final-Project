#include "utils.h"

int main()
{
	string client_cert_path, client_cert, recipient, encrypt_cert;
	client_cert_path = "./client.cert.pem";
	cout << "Enter recipient name (only addleness contains a valid cert right now): ";
	cin >> recipient;

	// get the client cert
	client_cert = ReadFiletoString(client_cert_path.c_str());
	// verify the client cert
	if (VerifyCert(client_cert))
	{
		// get the cert for encryption
		encrypt_cert = GetCert(recipient);
		// send back that cert
		WriteStringtoFile(encrypt_cert, "./encrypt.cert.pem");
	}
	//remove("./tmp/client.cert.pem");

	string message_path, message;
	message_path = "./message";

	// get the encrypted message
	message = ReadFiletoString(message_path.c_str());
	// upload the message
	UploadMessage(message, recipient);

	return 0;
}