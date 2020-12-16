#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

using namespace std;

string ReadFiletoString(const char *filename);

void WriteStringtoFile(string file, string filename);

bool isValidCert(string filename);

bool isValidRecipient(string recipient);

string ReturnCert(string recipient);

string GetCert(string recipient);

bool VerifyCert(string client_cert);