# ---- Build stage: compile a static binary ----
FROM golang:1.27.1 AS build

WORKDIR /src

# Download modules in their own layer so code changes don't refetch them.
COPY go.mod go.sum ./
RUN go mod download

COPY *.go ./

# CGO_ENABLED=0 gives a fully static binary (no libc), which is what lets
# it run on distroless/static. -trimpath drops local paths from the binary;
# -s -w strip debug symbols.
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/exporter .

# ---- Final stage: no shell, no package manager, non-root (uid 65532) ----
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=build /out/exporter /exporter

EXPOSE 9187
ENTRYPOINT ["/exporter"]
