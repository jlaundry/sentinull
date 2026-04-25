FROM golang:1.25-alpine AS builder

WORKDIR /src
COPY go.mod ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /sentinull

FROM scratch
COPY --from=builder /sentinull /sentinull
EXPOSE 8564
ENTRYPOINT ["/sentinull"]
