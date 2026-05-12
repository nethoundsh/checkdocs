# syntax=docker/dockerfile:1
FROM golang:1.26 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /out/server ./cmd/server
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /out/scraper ./cmd/scraper
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /out/research-sync ./cmd/research-sync
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /out/agent ./cmd/agent

FROM gcr.io/distroless/static-debian12
WORKDIR /app
COPY --from=build /out/server /app/server
COPY --from=build /out/scraper /app/scraper
COPY --from=build /out/research-sync /app/research-sync
COPY --from=build /out/agent /app/agent
EXPOSE 8080
ENTRYPOINT ["/app/server"]
CMD ["-addr", ":8080", "-db", "/app/data/docs.db"]

# research-sync-runner: clones the vulnerability-research repo then indexes it.
# Used by docker-compose --profile research; requires no host-side notebook clone.
FROM alpine:3.21 AS research-sync-runner
RUN apk add --no-cache git
COPY --from=build /out/research-sync /app/research-sync
WORKDIR /app
CMD ["sh", "-c", "git clone --depth=1 https://github.com/vulncheck-oss/vulnerability-research /tmp/research && /app/research-sync -db /app/data/docs.db -research /tmp/research"]
