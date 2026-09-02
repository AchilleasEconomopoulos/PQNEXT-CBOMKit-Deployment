# TLS certificates

Place the TLS certificate files used by Nginx in this directory before starting
the deployment:

```text
pki/
├── server.crt
├── server.key
└── ca.crt
```

- `server.crt` is the server certificate, including any intermediate
  certificates required to present a complete chain.
- `server.key` is the private key corresponding to `server.crt`.
- `ca.crt` is the CA certificate used to verify client certificates on port
  `8443`. It is not necessarily the CA that issued `server.crt`.

The certificate files are intentionally excluded from Git. Only this README is
tracked.

The default location is `./pki`. To use a different host directory, set an
absolute `PKI_DIR` in `.env`, for example:

```dotenv
PKI_DIR=/etc/cbomkit/pki
```

Recommended permissions for the default location are:

```sh
chmod 755 ./pki
chmod 644 ./pki/server.crt ./pki/ca.crt
chmod 600 ./pki/server.key
```

Docker Compose will stop with an error if any required file is missing rather
than creating an empty directory in its place.
