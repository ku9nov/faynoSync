FROM golang:latest AS builder

WORKDIR /go/src/app

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o faynoSync .

FROM golang:bullseye

WORKDIR /app

COPY --from=builder /go/src/app/mongod/migrations /app/mongod/migrations
COPY --from=builder /go/src/app/faynoSync /usr/bin

CMD ["faynoSync", "--migration"]
