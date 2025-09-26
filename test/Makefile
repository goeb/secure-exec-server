
all: test.cert

%.key:
	openssl ecparam -name prime256v1 -genkey -out $@

%.cert: %.key
	openssl req -x509 -key $< -out $@ -subj "/CN=$</" -days 3650
