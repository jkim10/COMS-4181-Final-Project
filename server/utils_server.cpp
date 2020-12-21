#include "utils_server.h"

#define USERNAME_MAX 255

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

bool isValidRecipient(string recipient)
{
	if (recipient.length() == 0 || recipient.length() > USERNAME_MAX)
	{
		return false;
	} 
	if (!isalpha(recipient[0]))
	{
		return false;
	}
	for (char const& c : recipient)
	{
		if (!isalpha(c) && !isdigit(c) && c != '+' && c != '-' && c != '_')
		{
			return false;
		}
	}

	string user_path = "./mailbox/users/" + recipient;
	if (access(user_path.c_str(), F_OK) == -1)
	{
		cerr << "Invalid recipient: " << recipient << endl;

		return false;
	}
	else
	{
		return true;
	}
}

string ReturnCert(string recipient)
{
	string cert_path = "./mailbox/users/" + recipient + "/certs/encrypt.cert.pem";
	fprintf(stderr, "CERTPATH: %s\n", cert_path.c_str());
	if (access(cert_path.c_str(), F_OK) == -1)
	{
		cerr << "Lack of suitable cert for " << recipient << endl;
		return ".\n";
	}
	
	return ReadFiletoString(cert_path.c_str());
}

string GetCert(string recipient)
{
	if (isValidRecipient(recipient))
		return ReturnCert(recipient);
	else
		return ".\n";
}

int SigVerify(const char* cert_pem, const char* intermediate_pem)
{
	BIO *b = BIO_new(BIO_s_mem());
	BIO_puts(b, intermediate_pem);
	X509 *issuer = PEM_read_bio_X509(b, NULL, NULL, NULL);
	EVP_PKEY* signing_key = X509_get_pubkey(issuer);

	BIO* c = BIO_new(BIO_s_mem());
	BIO_puts(c, cert_pem);
	X509* x509 = PEM_read_bio_X509(c, NULL, NULL, NULL);

	int res = X509_verify(x509, signing_key);

	EVP_PKEY_free(signing_key);
	BIO_free(b);
	BIO_free(c);
	X509_free(x509);
	X509_free(issuer);

	return res;
}

bool isValidCert(const char* client_cert_path, const char* intermediate_cert_path)
{
	SSL_CTX *ctx = SSL_CTX_new(TLS_method());
	if (SSL_CTX_load_verify_locations(ctx, client_cert_path, nullptr) != 1)
	{
		cerr << "Invalid cert: possibly not even a cert" << endl;
		SSL_CTX_free(ctx);
		return false;
	}
	SSL_CTX_free(ctx);

	string client_cert = ReadFiletoString(client_cert_path);
	string intermediate_cert = ReadFiletoString(intermediate_cert_path);

	if (SigVerify(client_cert.c_str(), intermediate_cert.c_str()) <= 0)
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

bool VerifyCert(string client_cert)
{
	WriteStringtoFile(client_cert, "./mailbox/tmp/client.cert.pem");
	return isValidCert("./mailbox/tmp/client.cert.pem", "./mailbox/tmp/intermediate.cert.pem");
}

bool isNumeric(const string &str)
{
	return all_of(str.begin(), str.end(), ::isdigit);
}

void NamePlusOne(char filename[])
{
	for (int i = strlen(filename)-1; i >= 0; --i)
	{
		if (filename[i] < '9')
		{
			filename[i] += 1;
			break;
		}
		else
		{
			filename[i] = '0';
		}
	}
}

void NameMinusOne(char filename[])
{
	for (int i = strlen(filename)-1; i >= 0; --i)
	{
		if (filename[i] > '0')
		{
			filename[i] -= 1;
			break;
		}
		else
		{
			filename[i] = '9';
		}
	}
}

// 1 is error, 0 is good
int UploadMessage(string message, string recipient)
{
	string user_path = "./mailbox/users/" + recipient + "/messages";
	DIR *dir = opendir(user_path.c_str());
	if (dir == NULL)
	{
		cerr << "Cannot upload message for " << recipient << endl;
		return 1;
	}
	
	char last_file[] = "00000";
	struct dirent* entry;
	while ((entry = readdir(dir)) != NULL)
	{
		if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0)
		{
			if (strlen(entry->d_name) == 5 && isNumeric(entry->d_name))
			{
				if (strcmp(entry->d_name, last_file) > 0)
				{
					strcpy(last_file, entry->d_name);
				}
			}
			else
			{
				cerr << "Invalid messges contained" << endl;
				return 1;
			}
		}
	}

	closedir(dir);

	if (strcmp(last_file, "99999") == 0)
	{
		cerr << "Full" << endl;
		return 1;
	}

	NamePlusOne(last_file);

	string file_path = "./mailbox/users/" + recipient + "/messages/" + last_file;

	WriteStringtoFile(message, file_path);

	return 0;
}

// 1 is error, 0 is good
int ParseAts(string content, string &user, string &message)
{
	if (content.length() < 3)
	{
		cerr << "Too short a body" << endl;
		return 1;
	}
	if (content[0] != '@')
	{
		cerr << "Lack of start @" << endl;
		return 1;
	}

	size_t user_start = 1;
	size_t user_end = content.find("@", user_start + 1);
	if (user_end >= content.length())
	{
		cerr << "Lack of end @" << endl;
		return 1;
	}
	else if (user_end == content.length() - 1)
	{
		cerr << "Empty message/Invalid cert" << endl;
		return 1;
	}

	user = content.substr(user_start, user_end - user_start);
	message = content.substr(user_end + 1, content.length() - user_end - 1);

	return 0;
}

// 1 is error, 0 is good
int ParseMessages(string content)
{
	string recipient, message;
	int stat_code = ParseAts(content, recipient, message);
	if (stat_code == 0 && isValidRecipient(recipient))
		return UploadMessage(message, recipient);
	return 1;
}

string GetMessage(string recipient)
{
	if (!isValidRecipient(recipient))
		return "";

	string user_path = "./mailbox/users/" + recipient + "/messages";
	DIR *dir = opendir(user_path.c_str());
	if (dir == NULL)
	{
		cerr << "Cannot get messages" << endl;
		return "";
	}

	char last_file[] = "00000";
	struct dirent* entry;
	while ((entry = readdir(dir)) != NULL)
	{
		if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0)
		{
			if (strlen(entry->d_name) == 5 && isNumeric(entry->d_name))
			{
				if (strcmp(entry->d_name, last_file) > 0)
				{
					strcpy(last_file, entry->d_name);
				}
			}
			else
			{
				cerr << "Invalid messges contained" << endl;
				return "";
			}
		}
	}
	closedir(dir);

	// rename all files
	char filename[] = "00001";
	while (strcmp(filename, last_file) <= 0)
	{
		string oldname = filename;
		NameMinusOne(filename);
		string newname = filename;
		rename((user_path + "/" + oldname).c_str(), (user_path + "/" + newname).c_str());
		NamePlusOne(filename);
		NamePlusOne(filename);
	}

	string message_path = user_path + "/00000";
	if (access(message_path.c_str(), F_OK) == -1)
	{
		cerr << "No new messages" << endl;
		return "";
	}

	string message = ReadFiletoString(message_path.c_str());
	remove(message_path.c_str());
	return message;
}

string ParseSendmsg(string content, vector<string> &recipients)
{
	if (content.back() != '\n')
	{
		cerr << "Wrong format: need a new line at the end" << endl;
		return "";
	}

	size_t found = content.find("-----END CERTIFICATE-----") + 25 + 1;
	if (found > content.length())
	{
		cerr << "Invalid certificate: lack of end of certificate" << endl;
		return "";
	}

	string client_cert = content.substr(0, found);
	content = content.substr(found, content.length()-found);
	while (content.length() > 0)
	{
		found = content.find('\n');
		recipients.push_back(content.substr(0, found));
		content = content.substr(found+1, content.length()-found-1);
	}

	return client_cert;
}

string CertstoSend(string client_cert, vector<string> recipients)
{
	string encrypt_certs = "";
	if (VerifyCert(client_cert))
	{
		for (int i = 0; i < recipients.size(); ++i)
		{
			encrypt_certs += GetCert(recipients[i]);
		}
	}

	return encrypt_certs;
}

string ParseCN(string cert_pem)
{
	BIO *b = BIO_new(BIO_s_mem());
	BIO_puts(b, cert_pem.c_str());
	X509 *subject = PEM_read_bio_X509(b, NULL, NULL, NULL);
	X509_NAME *subject_name = X509_get_subject_name(subject);

	char common_name[256];
	X509_NAME_get_text_by_NID(subject_name, NID_commonName, common_name, sizeof(common_name));

	return common_name;
}

string ParseRecvmsg(string content)
{
	string message = "";
	string recipient;
	string client_cert = content;

	//int stat_code = ParseAts(content, recipient, client_cert);
	//if (stat_code == 1)
	//	return "";
	
	if (VerifyCert(client_cert))
	{
		recipient = ParseCN(client_cert);
		//cout << recipient << endl;
		//recipient = "addleness";
		message = GetMessage(recipient);
	}

	return message;
}