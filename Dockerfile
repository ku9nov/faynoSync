FROM --platform=$BUILDPLATFORM golang:1.26.3 AS builder

ARG TARGETOS
ARG TARGETARCH

WORKDIR /go/src/app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags="-s -w" -o /out/faynoSync .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go test -c -o /out/faynoSync_tests

RUN mkdir -p /out/app && cp LICENSE /out/app/LICENSE

FROM gcr.io/distroless/static-debian12:nonroot AS base

COPY --from=builder --chown=nonroot:nonroot /out/app /app
COPY --from=builder /out/faynoSync /usr/bin/faynoSync

WORKDIR /app

# distroless has no curl/wget, so the binary probes /health itself
HEALTHCHECK --interval=10s --timeout=10s --start-period=10s --retries=3 \
    CMD ["/usr/bin/faynoSync", "healthcheck"]

CMD ["/usr/bin/faynoSync"]

# Local compose and CI: ships the integration test binary
FROM base AS dev

COPY --from=builder /out/faynoSync_tests /usr/bin/faynoSync_tests

FROM base AS runtime

ENV GIN_MODE=release
