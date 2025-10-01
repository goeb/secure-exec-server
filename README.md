# Secure Exec Server

Secure Exec Server let users submit their bash script to the server that will
authenticate and execute it.


## Build, test, install

Prerequisites:
- Linux operating system (tested on Ubuntu 22.04)
- meson build system
- glib-2.0
- openssl 3

Configure and compile:
```
meson setup build
cd build
meson configure --prefix /usr
meson compile
```

Test:
```
meson test
...
1/8 basic                     OK              0.54s
2/8 shutdown                  OK              0.51s
3/8 auth_invalid_input        OK              0.53s
4/8 auth_signature            OK              0.57s
5/8 keyusage                  OK              0.03s
6/8 child_process             OK              2.54s
7/8 child_parallel            OK              2.58s
8/8 certificates              OK              0.55s
...
```

Install
```
meson install --destdir installdir
```

The Secure Exec Server binary gets installed in: `installdir/usr/bin/ses`


## Usage

```
usage: ses TCP-PORT CERTIFICATE ...

Start a TCP server where clients can submit their scripts, that get
authenticated and executed.

Arguments:
  CERTIFICATE  X509 certificate whose public key is used for authentication.
               It must be in PEM encoding.
               It must carry the x509v3 extension KeyUsage 'digitalSignature'.
               If several certificates are specified, the authentication
               will succeed if at least 1 certificate verifies the signature.
  TCP-PORT     Listening port
```

Exit status:

- 0 when the server is shutdown by a client request
- 1 on error (listen error, no certificate with 'digitalSignature', ...)


## Quick start

First, create an ECC key and self-signed certificate:
```
openssl ecparam -name prime256v1 -genkey -out test.key
openssl req -x509 -key test.key -out test.cert -subj "/CN=test/" -days 3650 -addext keyUsage=digitalSignature
```
You can also use RSA keys.

**Start the server:**

Start a server that loads the public key and listens on `TCP-PORT`:
```
$ ses 4455 test.cert
Pulic key loaded from test.cert
Server listening on TCP port 4455
```

**As a client:**

- Prepare your script:
```
$ cat > example-script << EOF
echo "the quick brown fox"
EOF
```

- Sign your script, and get the hex dump of the DER signature:
```
$ openssl dgst -sha256 -sign test.key -hex example-script \
    | sed -e "s/.*= */# /" > example-script.sig
```

- Submit this signature as the first line of the script and the script:
```
$ cat example-script.sig example-script | socat - TCP:localhost:4455
```

- Test sending a script with an invalid signature:
```
$ socat - TCP:localhost:4455 << EOF
# 0123456789ABCDEF
echo "other script..."
EOF
```


When done, a client can shut down the server by sending `shutdown\n`:
```
echo shutdown | socat - TCP:localhost:4455
```
This will immediately disconnect all connected clients and make the server stop.

On the server side, we get something like:
```
0: new client connected
0: disconnected
0: number of bytes received: 170
0: authentication OK by ../test/test.cert
0: bash script started (pid=22961)
0: all bytes sent to child's stdin
0: output: the quick brown fox
0: child terminated (pid=22961) ok
1: new client connected
1: disconnected
1: number of bytes received: 42
1: authentication FAILED: verification failed
2: new client connected
2: disconnected
2: number of bytes received: 9
2: shutdown requested
exiting
```


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

Example:
```
# 304502206e0b9a8542d60c67128f90dd1fdb4965c5e452b5a9e229dd87c19eb18ca88613022100c3ba34de28298536485567724783055b5f58bb5b841296bc643343b315a4a383
echo "the quick brown fox"
```


## License

GPLv2. See [LICENSE](LICENSE).
