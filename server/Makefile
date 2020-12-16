all: server
	#openssl ecparam -genkey -name prime256v1 -noout -out server-private-key.pem
	#openssl ec -in server-private-key.pem -pubout -out server-public-key.pem
	#openssl req -new -x509 -sha256 -key server-private-key.pem -subj "/CN=duckduckgo.com" -out server-certificate.pem
	
server:
	g++ server.cpp -o server -lssl -lcrypto

clean:
	rm server
	#rm -r srv_certs/ srv_keys/ client_certs/ client_keys/
