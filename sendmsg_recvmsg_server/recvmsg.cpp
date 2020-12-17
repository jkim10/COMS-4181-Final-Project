#include "utils.h"

int main()
{
	string client_cert_path, client_cert, recipient, encrypt_cert;
	client_cert_path = "./client.cert.pem";
	cout << "Enter recipient name: ";
	cin >> recipient;

	string message;
	// get the client cert
	client_cert = ReadFiletoString(client_cert_path.c_str());
	// verify the client cert
	if (VerifyCert(client_cert))
	{
		// send back a message
		message = GetMessage(recipient);
		// send back the message
		WriteStringtoFile(message, "./newmessage");
	}
	//remove("./tmp/client.cert.pem");

	return 0;
}