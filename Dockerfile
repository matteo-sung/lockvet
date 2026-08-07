# syntax=docker/dockerfile:1
FROM golang:1.26-alpine@sha256:0178a641fbb4858c5f1b48e34bdaabe0350a330a1b1149aabd498d0699ff5fb2 AS build
ARG VERSION=dev
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 go build -trimpath \
      -ldflags "-s -w -X main.version=${VERSION}" -o /lockvet .

FROM alpine:3.24@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b
# git: local mode (`lockvet [rev]`) reads lockfiles straight from git.
# ca-certificates: OSV.dev / deps.dev / forge APIs over HTTPS.
# safe.directory '*': CI runners mount repos owned by a different uid.
RUN apk add --no-cache git ca-certificates \
 && git config --system --add safe.directory '*'
COPY --from=build /lockvet /usr/local/bin/lockvet

LABEL org.opencontainers.image.title="lockvet" \
      org.opencontainers.image.source="https://github.com/matteo-sung/lockvet" \
      org.opencontainers.image.description="Explain any lockfile change: bumps, breaking jumps, vulnerabilities introduced & fixed, release ages, deprecations — across 29 lockfile formats." \
      org.opencontainers.image.licenses="MIT" \
      io.modelcontextprotocol.server.name="io.github.matteo-sung/lockvet"

CMD ["lockvet", "-h"]
