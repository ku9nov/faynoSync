FROM --platform=$BUILDPLATFORM node:24-alpine@sha256:8a32c8cf649a49915a66e81e7a609223c708d0adabf288ee3f4077d765542f85 AS ui

WORKDIR /src/dashboard

COPY dashboard/package.json dashboard/yarn.lock ./
RUN yarn install --frozen-lockfile

COPY dashboard/ ./
RUN yarn build

FROM --platform=$BUILDPLATFORM golang:1.26.10@sha256:670bb5aa5349ae03b8516764718486f4f16399134bdc9acd0c46a23f043ab05c AS builder

ARG TARGETOS
ARG TARGETARCH

WORKDIR /go/src/app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
COPY --from=ui /src/server/dashboard/ui/dist server/dashboard/ui/dist

RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags="-s -w" -o /out/faynoSync .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go test -c -o /out/faynoSync_tests

RUN mkdir -p /out/app && cp LICENSE /out/app/LICENSE

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab AS base

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
