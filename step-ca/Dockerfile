FROM docker.io/library/golang:1.25-alpine@sha256:1ae0735f00daffa3aaf1363a5184c0d2dc55c78e3db4ec70241cdac97bf84b59 AS cli-builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/pqnext-cbomkitctl ./cmd/pqnext-cbomkitctl

FROM docker.io/smallstep/step-ca:0.30.2@sha256:a2b17872915c193259b75a5474c398326f41bd199f0842093e52cf4182bc8270

USER root
COPY --from=cli-builder /out/pqnext-cbomkitctl /usr/local/bin/pqnext-cbomkitctl
COPY step-ca/bin/pqnext-cbomkit-pki /usr/local/bin/pqnext-cbomkit-pki
COPY step-ca/templates /usr/local/share/pqnext-cbomkit/templates
RUN cp /usr/local/bin/step-ca /tmp/step-ca-unprivileged \
    && mv /tmp/step-ca-unprivileged /usr/local/bin/step-ca \
    && chmod 0755 /usr/local/bin/step-ca /usr/local/bin/pqnext-cbomkitctl /usr/local/bin/pqnext-cbomkit-pki \
    && chmod 0644 /usr/local/share/pqnext-cbomkit/templates/*.tpl

USER step
ENTRYPOINT ["/usr/local/bin/pqnext-cbomkit-pki"]
CMD ["serve"]
