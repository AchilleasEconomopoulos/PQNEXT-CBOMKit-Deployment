# PQNEXT-CBOMKit Deployment

This package deploys PQNEXT-CBOMKit and its TLS boundary as one Docker Compose
project. It supports a bundled private CA for installations without usable PKI,
or certificate import from an operator-managed PKI. The host-facing management
surface is the cross-platform `pqnext-cbomkitctl` executable; no host shell
scripts are required.

## Prerequisites

- Docker Engine or Docker Desktop using Linux containers
- Docker Compose v2 (`docker compose`)
- network access to the public GitHub release and container registries
- optional configuration through environment variables or a file based on
  `.env.example`

Build the management CLI with `go build ./cmd/pqnext-cbomkitctl`, or use a
platform binary from a `cli-v*` release.

Global and command help (`--help` or `-h`) work without a deployment directory,
installation state, or Docker. Deployment files are located only when a command
needs to operate on the stack.

## Install a deployment release

Download the CLI, then run:

```text
pqnext-cbomkitctl install --stack-version 1.0.0 \
  --pki managed --server-ip 192.0.2.10 --server-dns pqnext-cbomkit.example
```

The CLI downloads `pqnext-cbomkit-stack-v1.0.0.tar.gz` and `SHA256SUMS`
from the public `stack-v1.0.0` release, verifies the archive's SHA-256 checksum,
and extracts it into `~/.pqnext/cbomkit/stacks/stack-v1.0.0/`. No Git checkout,
GitHub authentication, or host Go installation is required. Versions can be
given as `1.0.0`, `v1.0.0`, or `stack-v1.0.0`; prereleases such as `1.0.0-rc.1`
are also accepted. There is no automatic selection of the latest release.

`--env-file PATH` is optional. If omitted, Compose uses environment variables,
an existing deployment `.env` if present, and its configured defaults. To supply
a configuration file, create one such as `deployment.env` using `.env.example`
as a template, and add `--env-file deployment.env` to the install command. The
CLI copies it into the deployment's `.env` with private file permissions where
supported. Repeating the same configuration is allowed; existing configuration
with different contents is never overwritten. The source configuration file is
preserved. Protect both files because they may contain credentials.

The stack version and directory are recorded in the existing home-directory
state file. Later commands and installation retries reuse that directory from
any working directory. A retry can omit `--stack-version` and `--env-file`; a
retry specifying the same version reuses the downloaded bundle. Switching an
installed deployment to another stack version is not supported in this release.
The same download flags work with `--pki external` and its certificate flags.

For local development or a manually extracted deployment, run from the deployment
directory or pass `--project-dir PATH` before the command. `--project-dir` and
`--stack-version` cannot be combined. The examples below also work with this
local workflow.

## Release tags

- `cli-v1.0.0` triggers the CLI workflow and publishes platform binaries and
  their checksums.
- `stack-v1.0.0` triggers the deployment workflow and publishes the stack archive
  and its checksum. The archive includes Compose, NGINX, OPA, step-ca, the
  configuration template, and the Go source needed to build the PKI image.

Both workflows run on their respective tag pushes or through `workflow_dispatch`
with an existing matching tag supplied as the `tag` input. The stack workflow
packages an explicit list of tracked paths from the tagged commit; operator
`.env` files, tokens, local state, and recovery archives are not included.
The PKI image is still built locally by Docker during installation. Publishing
a prebuilt PKI image and supporting stack upgrades are deferred.

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

To copy the current public root certificate to SSH hosts, create a hosts file:

```text
# One user@host per line; blank lines are allowed
alice@192.0.2.21
scanner@192.0.2.22
scanner@client.example.com
```

Then run:

```text
pqnext-cbomkitctl pki distribute-ca --hosts hosts.txt
```

The command validates every host entry and the root fingerprint, creates
`~/.config/pqnext/` on each remote host, then copies `ca.crt` there with `scp`.
It uses normal SSH
host-key verification and authentication. It attempts every host, reports
failures, and returns a nonzero exit code if any copy fails. Copying the file
does not automatically add it to a system trust store; configure each client
to use the copied certificate. The encrypted recovery archive is never sent.

To replace the managed CA after the VM address changes, run:

```text
pqnext-cbomkitctl pki reinit-ca --server-ip 192.0.2.20 \
  --server-dns pqnext-cbomkit.example
```

This stops the deployment, removes its managed CA and NGINX PKI volumes, and
creates a new root, intermediate, server certificate, and recovery archive.
On a terminal, the CLI asks you to type `reinit-ca` before making changes.
Pass `--yes` to skip that prompt in an unattended run.
Application and database volumes are preserved. The old recovery archive is
also preserved on the host. Use `--root-password-file` and `--recovery-dir` for
unattended runs, as with `install`. Existing client certificates and enrollment
tokens stop working. Export the new root with `pki export-ca`, update client
trust stores, and issue new `client-token` values to re-enroll clients. If a
restart fails after the reset, rerun `install --pki managed` with the new IP and
the same optional DNS name to finish initialization. When `--server-dns` is
omitted, the recorded DNS name is retained; pass `--server-dns ""` to clear it.

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

To remove the deployment and its data, run:

```text
pqnext-cbomkitctl uninstall
```

Downloaded installations use the recorded deployment directory; local
installations can pass `--project-dir PATH`. Type
`uninstall` at the prompt, or pass `--yes` for unattended use. The command
removes the Compose containers and network, all application, database, and PKI
volumes, `~/.pqnext/cbomkit/state.json`, and the matching encrypted root
recovery archive recorded in that state. It also works after a partial install
with no readable state. In that case, custom recovery archives and other host
files cannot be identified and must be removed manually. Docker images, the
deployment checkout or downloaded stack directory, `.env`, the old project-local
state file, and separately exported certificates or tokens remain.

The chosen PKI mode, server identity, deployment directory, and downloaded stack
version (when applicable) are recorded in
`~/.pqnext/cbomkit/state.json` for the user running the CLI. The CLI creates
`~/.pqnext/cbomkit` with private permissions and uses platform-native paths on
non-Unix hosts. Run subsequent commands as the same user; `sudo` may select a
different home directory. Reinstalling is idempotent; changing mode or server
identity through `install` is rejected. Use `pki reinit-ca` to replace a managed
CA and change its server identity.

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
