# Secure Exec Server

Secure Exec Server let users submit their bash script to the server that will
authenticate and execute it.


## Build & install

Prerequisites:
- glib-2.0
- meson build system

To compile and install, run these commands:
```
meson setup build
cd build
meson configure --prefix /usr
meson compile
meson test
meson install --destdir installdir
```

The Secure Exec Server binary gets installed in: `installdir/usr/bin/ses`


## Usage & test

- Start the server and select a TCP listening port. Eg: `secure-exec-server 4455`

- As a client, submit your file and close the connection.

Example:
```
cat > example-script << EOF
the quick brown fox
EOF

socat - TCP:localhost:4455 << EOF
```




