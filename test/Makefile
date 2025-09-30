
SCRIPTS ?= example-script
SCRIPTS_SIGNED = $(SCRIPTS:%=%.signed)

all: test.cert $(SCRIPTS_SIGNED)

%.key:
	openssl ecparam -name prime256v1 -genkey -out $@

%.cert: %.key
	openssl req -x509 -key $< -out $@ -subj "/CN=$</" -days 3650 -addext keyUsage=digitalSignature

%.signed: % test.key
	openssl dgst -sha256 -sign test.key -hex $< | sed -e "s/.*= */# /" > $<.sig
	cat $<.sig $< > $@
	rm $<.sig
