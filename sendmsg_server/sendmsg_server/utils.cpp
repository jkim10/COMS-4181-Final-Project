#include "utils.h"

string ReadFiletoString(const char *filename)
{
	ifstream ifile(filename);
	ostringstream buf;
	char ch;
	while (buf&&ifile.get(ch))
		buf.put(ch);
	return buf.str();
}

void WriteStringtoFile(string file, string filename)
{
	FILE *fp;
	fp = fopen(filename.c_str(), "w+");
	fwrite(file.c_str(), sizeof(char), file.length(), fp);
	fclose(fp);
}

bool isValidCert(string filename)
{
	SSL_CTX *ctx = SSL_CTX_new(TLS_method());
	if (SSL_CTX_load_verify_locations(ctx, filename.c_str(), nullptr) != 1)
	{
		cout << "Invalid cert" << endl;
        return false;
	}
    else
    {
    	cerr << "Cert is valid" << endl;
    	return true;
    }
}

bool isValidRecipient(string recipient)
{
	string user_path = "./users/" + recipient;
	if (access(user_path.c_str(), F_OK) == -1)
	{
		cerr << "Invalid recipient: " << recipient << endl;
		return false;
	}
	else
		return true;
}

string ReturnCert(string recipient)
{
	string cert_path = "./users/" + recipient + "/certs/encrypt.cert.pem";
	if (access(cert_path.c_str(), F_OK) == -1)
	{
		cerr << "Lack of suitable cert for " << recipient << endl;
		return "";
	}
	
	return ReadFiletoString(cert_path.c_str());
}

string GetCert(string recipient)
{
	if (isValidRecipient(recipient))
		return ReturnCert(recipient);
	else
		return "";
}

bool VerifyCert(string client_cert)
{
	WriteStringtoFile(client_cert, "./tmp/client.cert.pem");
	return isValidCert("./tmp/client.cert.pem");
}