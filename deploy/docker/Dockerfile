# proteus in containers (spec 2026-10-09 §5, D3).
#
# Build from the repository root:
#
#   docker build -f deploy/docker/Dockerfile -t proteus:dev .                  # the server image
#   docker build -f deploy/docker/Dockerfile --target fetch -t proteus-fetch:dev .
#
# Two images come from this file:
#
# - mcp (the last stage, the default): the static binary on distroless, no
#   shell. It runs `proteus mcp --http` and reads the store read-only.
# - fetch: the same binary with a static busybox, whose shell runs
#   `proteus fetch --all` on a schedule. Only this image holds the inventory
#   with credentials.
#
# Both run as UID 10001, the owner of the store volume.

ARG GO_VERSION=1.26.9

FROM golang:${GO_VERSION}-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
ARG VERSION=dev
# A static binary: no cgo, so the pure Go DNS resolver and no libc.
RUN CGO_ENABLED=0 go build -trimpath -buildvcs=false \
        -ldflags "-s -w -X main.version=${VERSION}" -o /out/proteus ./cmd/proteus
# The directories the volumes mount on. An empty named volume takes their
# owner and mode at its first mount, so UID 10001 owns the store. COPY
# --from keeps the owners; their parents stay root's.
RUN install -d -m 0700 -o 10001 -g 10001 /out/root/var/lib/proteus /out/root/var/lib/proteus/store \
        /out/root/var/log/proteus

FROM busybox:1.37.0-musl AS fetch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/proteus /usr/local/bin/proteus
COPY --from=build /out/root/ /
COPY deploy/docker/fetch-loop.sh /usr/local/bin/fetch-loop
ENV HOME=/var/lib/proteus \
    PROTEUS_CONFIG=/run/secrets/proteus-inventory \
    PROTEUS_STORE=/var/lib/proteus/store \
    PROTEUS_LOG_DIR=/var/log/proteus/fetch
USER 10001:10001
ENTRYPOINT ["/usr/local/bin/fetch-loop"]

FROM gcr.io/distroless/static-debian12 AS mcp
COPY --from=build /out/proteus /usr/local/bin/proteus
COPY --from=build /out/root/ /
ENV HOME=/var/lib/proteus \
    PROTEUS_STORE=/var/lib/proteus/store \
    PROTEUS_LOG_DIR=/var/log/proteus/cli
USER 10001:10001
EXPOSE 8765
ENTRYPOINT ["/usr/local/bin/proteus"]
CMD ["mcp", "--http"]
