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

string GetMessage(string recipient)
{
	string user_path = "./users/" + recipient + "/messages";
	DIR *dir = opendir(user_path.c_str());
	if (dir == NULL)
	{
		cerr << "Cannot get messages" << endl;
		return "";
	}
	
	string message_path = user_path + "/00001";
	if (access(message_path.c_str(), F_OK) == -1)
	{
		cerr << "No new messages" << endl;
		return "";
	}

	closedir(dir);

	return ReadFiletoString(message_path.c_str());
}