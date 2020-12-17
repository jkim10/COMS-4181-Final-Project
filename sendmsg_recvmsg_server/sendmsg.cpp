#include "utils.h"

int main()
{
	string client_cert_path, client_cert, recipient_path, recipient, encrypt_cert;
	client_cert_path = "./client.cert.pem";
	recipient_path = "./recipients";
	//cout << "Enter recipient name (only addleness contains a valid cert right now): ";
	//cin >> recipient;

	// get the client cert and the list of recipients 
	client_cert = ReadFiletoString(client_cert_path.c_str());
	recipient = ReadFiletoString(recipient_path.c_str());

	string request = client_cert + recipient;
	vector<string> recipients;
	// parse the content and get the certs to send
	client_cert = ParseSendmsg(request, recipients);
	encrypt_cert = CertstoSend(client_cert, recipients);
	cout << encrypt_cert << endl;
	/*// verify the client cert
	if (VerifyCert(client_cert))
	{
		// get the cert for encryption
		encrypt_cert = GetCert(recipient);
		// send back that cert
		WriteStringtoFile(encrypt_cert, "./encrypt.cert.pem");
	}*/
	//remove("./tmp/client.cert.pem");

	string message_path, message;
	message_path = "./message";

	// get the encrypted message
	message = ReadFiletoString(message_path.c_str());
	// upload the message
	for (int i = 0; i < recipients.size(); ++i)
	{
		UploadMessage(message, recipients[i]);
	}

	return 0;
}