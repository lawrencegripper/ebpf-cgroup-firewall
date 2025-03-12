FROM mcr.microsoft.com/devcontainers/go:1-bookworm

USER root

# Install additional packages
COPY ./script/linux-dependencies /tmp/linux-dependencies
RUN /tmp/linux-dependencies

# Install mkcert
RUN curl -JLO "https://dl.filippo.io/mkcert/latest?for=linux/amd64" && \
    chmod +x mkcert-v*-linux-amd64 && \
    cp mkcert-v*-linux-amd64 /usr/local/bin/mkcert && \
    mkcert -install 

# Install mockery https://vektra.github.io/mockery/latest/installation/
RUN go install github.com/vektra/mockery/v2@v2.53.2

# Install netcat and curl which we need for smoke tests
RUN apt-get update && apt-get install -y ncat curl bpfcc-tools clang-format

# Avoid git safety messages on codespace build
RUN git config --global --add safe.directory '*'

# Install go releaser
RUN echo 'deb [trusted=yes] https://repo.goreleaser.com/apt/ /' | sudo tee /etc/apt/sources.list.d/goreleaser.list && \
    sudo apt update && \
    sudo apt install goreleaser
