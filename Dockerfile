FROM golang:1.26.1 AS builder

WORKDIR /go/src/app

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o faynoSync .
RUN CGO_ENABLED=0 GOOS=linux go test -c -o faynoSync_tests

FROM golang:1.26.1-alpine3.22

RUN addgroup -S faynosync && adduser -S -G faynosync faynosync

WORKDIR /app

COPY --from=builder /go/src/app/LICENSE /app/LICENSE
COPY --from=builder /go/src/app/mongod/migrations /app/mongod/migrations
COPY --from=builder /go/src/app/faynoSync /usr/bin
COPY --from=builder /go/src/app/faynoSync_tests /usr/bin

RUN chown -R faynosync:faynosync /app /usr/bin/faynoSync /usr/bin/faynoSync_tests

USER faynosync

CMD ["faynoSync", "--migration"]
