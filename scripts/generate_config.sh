#!/bin/bash

if [ $# -ne 4 ]; then
    echo "Usage: ./generate_config.sh <configfile_name> <directory> <common_name> <usr/server/root/intermediate/encrypt>"
    exit 1
fi

touch $1

echo [ ca ] >> $1
echo default_ca = CA_default >> $1
echo ' ' >> $1 
echo [ CA_default ] >> $1
echo "# Directory and file locations." >> $1
echo dir                = $2 >> $1
echo 'certs             = $dir/certs' >> $1
echo 'crl_dir           = $dir/crl'>> $1
echo 'new_certs_dir     = $dir/newcerts'>> $1
echo 'database          = $dir/index.txt'>> $1
echo 'serial            = $dir/serial'>> $1
echo 'RANDFILE          = $dir/private/.rand'>> $1
echo 'unique_subject    = no'>> $1 
echo ' ' >> $1 
echo "# The root key and root certificate." >> $1
if [ $4 == "root" ]; then
    echo 'private_key       = $dir/private/ca.key.pem'>> $1
    echo 'certificate       = $dir/certs/ca.cert.pem'>> $1
else
	echo 'private_key       = $dir/private/intermediate.key.pem'>> $1
	echo 'certificate       = $dir/certs/intermediate.cert.pem'>> $1
fi
echo " " >> $1 
echo "# For certificate revocation lists." >> $1
echo 'crlnumber         = $dir/crlnumber'>> $1
echo 'crl               = $dir/crl/ca.crl.pem'>> $1
echo crl_extensions    = crl_ext>> $1
echo default_crl_days  = 30 >> $1
echo default_md        = sha256 >> $1
echo name_opt          = ca_default>> $1
echo cert_opt          = ca_default>> $1
echo default_days      = 375 >> $1
echo preserve          = no>> $1
if [ $4 == "root" ]; then
        echo policy            = policy_strict>> $1
else
        echo policy            = policy_loose >> $1
fi
echo ' ' >> $1 
echo [ policy_strict ] >> $1
echo countryName             = match>> $1
echo stateOrProvinceName     = match>> $1
echo organizationName        = match>> $1
echo organizationalUnitName  = optional>> $1
echo commonName              = supplied>> $1
echo emailAddress            = optional>> $1
echo ' ' >> $1 
echo [ policy_loose ]>> $1
echo countryName             = optional>> $1
echo stateOrProvinceName     = optional>> $1
echo localityName            = optional>> $1
echo organizationName        = optional>> $1
echo organizationalUnitName  = optional>> $1
echo commonName              = supplied>> $1
echo emailAddress            = optional>> $1
echo ' ' >> $1 
echo [ req ]>> $1
echo default_bits        = 2048 >> $1
echo distinguished_name  = req_distinguished_name>> $1
echo string_mask         = utf8only>> $1
echo prompt              = no>> $1
echo default_md          = sha256 >> $1
echo x509_extensions     = v3_ca>> $1
echo ' ' >> $1 
echo [ req_distinguished_name ]>> $1
echo  countryName                     = US>> $1
echo  stateOrProvinceName             = New York >> $1
echo  localityName                    = New York >> $1
echo  0.organizationName              = Security 4181 >> $1
echo  organizationalUnitName          = Security 4181 >> $1
echo  commonName                      = $3 >> $1
echo  emailAddress                    = sarah@security.edu>> $1
echo ' ' >> $1 
echo [ v3_ca ]>> $1
echo subjectKeyIdentifier = hash>> $1
echo authorityKeyIdentifier = keyid:always,issuer>> $1
echo basicConstraints = critical, CA:true>> $1
echo keyUsage = critical, digitalSignature, cRLSign, keyCertSign >> $1
echo  ' '>> $1
echo [ v3_intermediate_ca ] >> $1
echo subjectKeyIdentifier = hash >> $1
echo authorityKeyIdentifier = keyid:always,issuer >> $1
echo basicConstraints = critical, CA:true, pathlen:0 >> $1
echo keyUsage = critical, digitalSignature, cRLSign, keyCertSign >> $1
echo ' ' >> $1
if [ $4 == usr ]; then
        echo [ usr_cert ] >> $1
        echo basicConstraints = CA:FALSE >> $1
        echo nsCertType = client, email >> $1
        echo nsComment = "OpenSSL Generated Client Certificate" >> $1
        echo subjectKeyIdentifier = hash >> $1
        echo authorityKeyIdentifier = keyid,issuer >> $1
        echo keyUsage = critical, nonRepudiation, digitalSignature, keyEncipherment >> $1
        echo extendedKeyUsage = clientAuth, emailProtection >> $1
elif [ $4 == encrypt ]; then
        echo [ usr_cert ] >> $1
        echo basicConstraints = CA:FALSE >> $1
        echo nsCertType = client, email >> $1
        echo nsComment = "OpenSSL Generated Client Certificate" >> $1
        echo subjectKeyIdentifier = hash >> $1
        echo authorityKeyIdentifier = keyid,issuer >> $1
        echo keyUsage = critical, nonRepudiation, digitalSignature, keyEncipherment, keyAgreement, \
              encipherOnly  >> $1
        echo extendedKeyUsage = clientAuth, emailProtection >> $1
elif [ $4 == server ]; then
        echo [ server_cert ] >> $1
        echo basicConstraints = CA:FALSE >> $1
        echo nsCertType = server >> $1
        echo nsComment = "OpenSSL Generated Server Certificate" >> $1
        echo subjectKeyIdentifier = hash >> $1
        echo authorityKeyIdentifier = keyid,issuer:always >> $1
        echo keyUsage = critical, digitalSignature, keyEncipherment >> $1
        echo extendedKeyUsage = serverAuth >> $1
        echo subjectAltName = @alternate_names >> $1
        echo [ alternate_names ] >> $1
	echo DNS.1 = $3 >> $1
fi

echo ' '  >> $1
echo [ crl_ext ] >> $1
echo authorityKeyIdentifier=keyid:always >> $1
echo ' '  >> $1
echo [ ocsp ] >> $1
echo basicConstraints = CA:FALSE >> $1
echo subjectKeyIdentifier = hash >> $1
echo authorityKeyIdentifier = keyid,issuer >> $1
echo keyUsage = critical, digitalSignature >> $1
echo extendedKeyUsage = critical, OCSPSigning >> $1
