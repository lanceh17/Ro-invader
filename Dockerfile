FROM golang:1.27-alpine AS builder
WORKDIR /src
COPY agent/go.mod agent/go.sum ./
RUN go mod download
COPY agent/ ./
RUN CGO_ENABLED=0 go build -o /out/r0-guard ./cmd/r0-guard

FROM alpine:3.20
RUN apk --no-cache add ca-certificates
COPY --from=builder /out/r0-guard /usr/local/bin/r0-guard
EXPOSE 53/udp 18080/tcp
ENTRYPOINT ["r0-guard"]
