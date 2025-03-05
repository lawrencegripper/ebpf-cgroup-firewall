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

# Avoid git safety messages on codespace build
RUN git config --global --add safe.directory '*'