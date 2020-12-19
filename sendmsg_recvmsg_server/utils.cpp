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
	SSL_CTX* ctx = SSL_CTX_new(TLS_method());
	if (SSL_CTX_load_verify_locations(ctx, filename.c_str(), nullptr) != 1)
	{
		cout << "Invalid cert" << endl;
		SSL_CTX_free(ctx);
		return false;
	}
	else
	{
		cerr << "Cert is valid" << endl;
		SSL_CTX_free(ctx);
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
	{
		return true;
	}
}

string ReturnCert(string recipient)
{
	string cert_path = "./users/" + recipient + "/certs/encrypt.cert.pem";
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

bool VerifyCert(string client_cert)
{
	WriteStringtoFile(client_cert, "./tmp/client.cert.pem");
	return isValidCert("./tmp/client.cert.pem");
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

void UploadMessage(string message, string recipient)
{
	string user_path = "./users/" + recipient + "/messages";
	DIR *dir = opendir(user_path.c_str());
	if (dir == NULL)
	{
		cerr << "Cannot upload message for " << recipient << endl;
		return;
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
				return;
			}
		}
	}

	closedir(dir);

	if (strcmp(last_file, "99999") == 0)
	{
		cerr << "Full" << endl;
		return;
	}

	NamePlusOne(last_file);

	string file_path = "./users/" + recipient + "/messages/" + last_file;

	WriteStringtoFile(message, file_path);
}

void ParseMessages(string content)
{
	size_t user_start = 1;
	size_t user_end = content.find("@", user_start + 1);
	string recipient = content.substr(user_start, user_end - user_start);
	string message = content.substr(user_end + 1, content.length() - user_end - 1);
	UploadMessage(message, recipient);
}

string GetMessage(string recipient)
{
	string user_path = "./users/" + recipient + "/messages";
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

	return ReadFiletoString(message_path.c_str());
}

string ParseSendmsg(string content, vector<string> &recipients)
{
	if (content[content.length()-1] != '\n')
	{
		cerr << "Wrong format" << endl;
		return "";
	}

	size_t found = content.find("-----END CERTIFICATE-----") + 25 + 1;
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
	string encrypt_certs;
	if (VerifyCert(client_cert))
	{
		for (int i = 0; i < recipients.size(); ++i)
		{
			encrypt_certs += GetCert(recipients[i]);
		}
	}

	return encrypt_certs;
}