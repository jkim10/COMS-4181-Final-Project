#!/bin/bash

openssl s_client -connect localhost:8080 -key myclient.key.pem -cert myclient.cert.pem -CAfile ca-chain.cert.pem -verify 10