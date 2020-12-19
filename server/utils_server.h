#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <dirent.h>
#include <algorithm>
#include <sys/stat.h>
#include <sys/types.h>
#include <vector>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

using namespace std;

string ReadFiletoString(const char *filename);

void WriteStringtoFile(string file, string filename);

string GetCert(string recipient);

bool VerifyCert(string client_cert);

void UploadMessage(string message, string recipient);

void ParseMessages(string content);

string GetMessage(string recipient);

string ParseSendmsg(string content, vector<string> &recipients);

string CertstoSend(string client_cert, vector<string> recipients);