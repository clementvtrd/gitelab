# syntax=docker/dockerfile:1

FROM golang:1.27-alpine AS build
RUN apk add --no-cache git ca-certificates
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/gitelab .

FROM alpine:3.21
RUN apk add --no-cache git ca-certificates tzdata \
 && addgroup -S gitelab && adduser -S gitelab -G gitelab
COPY --from=build /out/gitelab /usr/local/bin/gitelab
ENV GITELAB_DATA_DIR=/data \
    GITELAB_HTTP_ADDR=:3000 \
    GITELAB_SSH_ADDR=:2222 \
    GITELAB_EXTERNAL_URL=http://localhost:3000
VOLUME ["/data"]
USER gitelab
EXPOSE 3000 2222
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s \
  CMD wget -q -O /dev/null http://127.0.0.1:3000/healthz || exit 1
ENTRYPOINT ["gitelab"]
