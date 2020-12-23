#pragma once

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
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/cms.h>
#include <openssl/asn1.h>


using namespace std;

string ReadFiletoString(const char *filename);

void WriteStringtoFile(string file, string filename);

string GetCert(string recipient);

bool VerifyCert(string client_cert);

int UploadMessage(string message, string recipient);

int ParseMessages(string content);

string GetMessage(string recipient);

string ParseSendmsg(string content);

string CertstoSend(string client_cert, vector<string> recipients);

string ParseRecvmsg(string content);

string ParseSignature(string content);

vector<string> ParseRecipients(string content);