# Build
FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /out/auth-server ./cmd/server

# Run — templates are embedded in the binary (internal/handler/templates.go).
FROM alpine:3.22
RUN apk add --no-cache ca-certificates tzdata
COPY --from=build /out/auth-server /usr/local/bin/auth-server
EXPOSE 8080
USER nobody
ENTRYPOINT ["auth-server"]
