all: server
	cp $(HOME)/ca/intermediate/certs/www.mysite.com.cert.pem server-certificate.pem
	cp $(HOME)/ca/intermediate/private/www.mysite.com.key.pem server-private-key.pem
	
	cp $(HOME)/ca/intermediate/certs/myclient.cert.pem myclient.cert.pem
	cp $(HOME)/ca/intermediate/private/myclient.key.pem myclient.key.pem

	cp $(HOME)/ca/intermediate/certs/ca-chain.cert.pem ca-chain.cert.pem
server:
	g++ server.cpp -o server -lssl -lcrypto

clean:
	rm server server-private-key.pem server-certificate.pem myclient.cert.pem myclient.key.pem ca-chain.cert.pem
	rm -rf $(HOME)/ca