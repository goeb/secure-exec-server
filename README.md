# Secure Exec Server

Secure Exec Server let users submit their bash script to the server that will
authenticate and execute it.


## Build & install

Prerequisites:
- Linux operating system (tested on Ubuntu 22.04)
- meson build system
- glib-2.0
- openssl 3

To compile, test and install, run these commands:
```
meson setup build
cd build
meson configure --prefix /usr
meson compile
meson test
meson install --destdir installdir
```

The Secure Exec Server binary gets installed in: `installdir/usr/bin/ses`


## Quick start

First, create an ECC key and self-signed certificate:
```
openssl ecparam -name prime256v1 -genkey -out test.key
openssl req -x509 -key test.key -out test.cert -subj "/CN=test/" -days 3650
```

**Start the server:**

Start a server that loads the public key and listens on `TCP-PORT`:
```
ses 4455 test.cert
```

**As a client:**

- Prepare your script:
```
cat > example-script << EOF
echo "the quick brown fox"
EOF
```

- Sign your script, and get the hex dump of the DER signature:
```
openssl dgst -sha256 -sign test.key -hex example-script \
    | sed -e "s/.*= */# /" > example-script.sig
```

- Submit this signature as the first line of the script and the script:
```
cat example-script.sig example-script | socat - TCP:localhost:4455
```


When done, a client can shut down the server by sending `shutdown\n`:
```
echo shutdown | socat - TCP:localhost:4455
```
This will immediately disconnect all connected clients and make the server stop.


## Protocol

The protocol is quite simple.

From the client perspective:

- open a TCP connection to the server
- send the bytes of the script with the first line being the signature
- close the TCP connection

From the server perspective:

- accept an incoming TCP connection request
- read all bytes from the client until they close the connection
- process the request (authentication, ...)


## Format of the signature

The first line of the script must have the following format:

- the first character must be a `#`, followed by zero of more spaces
- hexadecimal dump of the DER signature (characters [0-9a-fA-F])
- ending LF character (`\n`), that marks the end of the signature line

All following bytes are the payload, and taken into account for computing the signature.

