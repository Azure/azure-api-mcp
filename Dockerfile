# Linux Dockerfile for azure-api-mcp
# Build stage
FROM golang:1.25-alpine AS builder
ARG TARGETOS=linux
ARG TARGETARCH
ARG VERSION
ARG GIT_COMMIT
ARG BUILD_DATE
ARG GIT_TREE_STATE

WORKDIR /app

COPY go.mod go.sum ./

RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build \
    -trimpath \
    -ldflags "-X github.com/Azure/azure-api-mcp/internal/version.GitVersion=${VERSION} \
              -X github.com/Azure/azure-api-mcp/internal/version.GitCommit=${GIT_COMMIT} \
              -X github.com/Azure/azure-api-mcp/internal/version.GitTreeState=${GIT_TREE_STATE} \
              -X github.com/Azure/azure-api-mcp/internal/version.BuildMetadata=${BUILD_DATE}" \
    -o azure-api-mcp ./cmd/server

# Runtime stage
FROM alpine:3.22
ARG TARGETARCH

RUN apk add --no-cache curl bash openssl ca-certificates git python3 py3-pip \
    gcc python3-dev musl-dev linux-headers

# Install kubectl
RUN echo $TARGETARCH; curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/${TARGETARCH}/kubectl" && \
    chmod +x kubectl && \
    mv kubectl /usr/local/bin/kubectl

# Install Azure CLI
RUN pip3 install --break-system-packages --no-cache-dir azure-cli

RUN addgroup -S mcp && \
    adduser -S -G mcp -h /home/mcp mcp && \
    mkdir -p /home/mcp/.azure && \
    chown -R mcp:mcp /home/mcp

COPY --from=builder /app/azure-api-mcp /usr/local/bin/azure-api-mcp

WORKDIR /home/mcp

EXPOSE 8000

USER mcp

ENV HOME=/home/mcp

ENTRYPOINT ["/usr/local/bin/azure-api-mcp"]
CMD ["--transport", "streamable-http", "--host", "0.0.0.0"]
