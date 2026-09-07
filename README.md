# PQNEXT-CBOMKit Deployment

This package deploys PQNEXT-CBOMKit and its TLS boundary as one Docker Compose
project. It supports a bundled private CA for installations without usable PKI,
or certificate import from an operator-managed PKI. The host-facing management
surface is the cross-platform `pqnext-cbomkitctl` executable; no host shell
scripts are required.

## Prerequisites

- Docker Engine or Docker Desktop using Linux containers
- Docker Compose v2 (`docker compose`)
- locally available `pqnext-cbomkit-backend` and
  `pqnext-cbomkit-frontend` images
- a populated `.env`; start from `.env.example`

Build the management CLI with `go build ./cmd/pqnext-cbomkitctl`, or use a
platform binary from the release artifacts. Run it from this directory, or pass
`--project-dir` before the command.

## Managed PKI

Interactive installation reads the recovery passphrase twice without echo:

```text
pqnext-cbomkitctl install --pki managed --server-ip 192.0.2.10 \
  --server-dns pqnext-cbomkit.example
```

For unattended installation, put the passphrase in a protected regular file
(`0600` or stricter on Unix) and pass only its path:

```text
pqnext-cbomkitctl install --pki managed --server-ip 192.0.2.10 \
  --server-dns pqnext-cbomkit.example --root-password-file /secure/input/passphrase
```

The passphrase is streamed to the initialization job over stdin. It is never a
command argument or environment variable and is not retained by the deployment.
The CLI writes an encrypted recovery bundle to the platform user-data directory
unless `--recovery-dir` is supplied. Retain both the archive and its passphrase;
neither can replace the other.

Initialization creates the root in a uniquely named, labeled bootstrap volume.
That volume is mounted only by the init and export jobs. Once the CLI has
validated and atomically saved the recovery archive, it marks the CA generation active and
removes the bootstrap volume. The online `step-ca` container runs as UID/GID
1000 and mounts only its CA state and intermediate-key password. Its wrapper
refuses startup if a root-key path is found in online state.

The initial NGINX identity has the requested IP and optional DNS SAN, is limited
to `serverAuth`, and is issued for 24 hours. Automatic renewal is not included
in this release.

Create a short-lived, identity-bound client enrollment token with:

```text
pqnext-cbomkitctl client-token --name scanner-01 --output scanner-01.token
```

The token file is created with mode `0600` where the platform supports Unix
permissions. Delivering and consuming that token is an enrollment operation,
not a routine server administration step.

Export the public root CA certificate for installation on clients with:

```text
pqnext-cbomkitctl pki export-ca --output ca.crt
```

The CLI validates the self-signed CA certificate and checks its fingerprint
against deployment state before atomically writing the public file. Distribute
this certificate only; never distribute the root recovery archive.

## External PKI

```text
pqnext-cbomkitctl install --pki external --server-ip 192.0.2.10 \
  --server-dns pqnext-cbomkit.example \
  --server-cert /native/path/server.crt \
  --server-key /native/path/server.key \
  --client-ca /native/path/client-ca.crt
```

The files have independent roles:

- `server.crt` is the NGINX leaf followed by all required issuing
  intermediates.
- `server.key` is the matching, unencrypted private key.
- `client-ca.crt` is the CA trust bundle for authenticating mTLS clients. It may
  be unrelated to the CA that issued `server.crt`.

The CLI reads native host paths, validates the material, and sends an in-memory
tar stream to an importer over stdin. No host certificate path is bind-mounted.
The importer validates again, stages a complete version in
`pqnext-cbomkit-nginx-pki`, and atomically switches the `current` symlink. Bad
input cannot replace the active set.

Rotate external material with the same protocol:

```text
pqnext-cbomkitctl pki import \
  --server-cert /native/path/server.crt \
  --server-key /native/path/server.key \
  --client-ca /native/path/client-ca.crt
```

NGINX is reloaded only after activation succeeds. External certificate issuance,
client enrollment, and renewal remain the external PKI operator's responsibility.

## Lifecycle and persistence

```text
pqnext-cbomkitctl up
pqnext-cbomkitctl status
pqnext-cbomkitctl down
```

The chosen PKI mode and server identity are recorded in
`.pqnext-cbomkit-state.json`. Reinstalling is idempotent; changing mode or server
identity is rejected because migration is not implemented.

The PKI volumes are Docker-external and therefore survive
`docker compose down -v`:

| Volume | Contents | Long-running mount |
|---|---|---|
| `pqnext-cbomkit-ca-data` | online CA config, DB, intermediate key | step-ca, read/write |
| `pqnext-cbomkit-ca-password` | intermediate-key password | step-ca, read-only |
| `pqnext-cbomkit-ca-admin-password` | admin provisioner password | configuration job only |
| `pqnext-cbomkit-ca-client-password` | client provisioner password | token job only |
| `pqnext-cbomkit-ca-server-password` | server provisioner password | issuance job only |
| `pqnext-cbomkit-ca-public` | root/intermediate certificates and fingerprint | PKI jobs, read-only |
| `pqnext-cbomkit-nginx-pki` | versioned active NGINX key and certificates | NGINX, read-only |

External mode creates only `pqnext-cbomkit-nginx-pki`; it neither creates CA
volumes nor starts step-ca. Do not use `docker volume rm` on these volumes as a
normal lifecycle operation.

Fresh-install detection intentionally refuses legacy files under `pki/`. Archive
or migrate them explicitly before installation. Managed/external migration,
automatic managed renewal, full CA restore, and intermediate rotation are
deferred.

## Security boundary

Routine users never need to open, copy, or permission the Docker-volume files.
The online intermediate key and the active NGINX server key necessarily remain
on the host in Docker-managed storage so those services can use them. Treat
Docker daemon access as root-equivalent: an operator who can run arbitrary
containers can mount and read those volumes. This deployment prevents accidental
host-path exposure and minimizes mounts; it cannot defend secrets from a Docker
administrator or a compromised host kernel.

The CLI never deletes operator-supplied external-PKI inputs. The external PKI
operator remains responsible for protecting or removing those source files. In
managed mode, the only host file created by the PKI workflow is the encrypted
root recovery archive; it is written atomically with restrictive permissions.
