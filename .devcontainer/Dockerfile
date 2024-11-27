FROM mcr.microsoft.com/devcontainers/go:1-bookworm

USER root

# Install additional packages
COPY ./script/linux-dependencies /tmp/linux-dependencies
RUN /tmp/linux-dependencies

# Avoid git safety messages on codespace build
RUN git config --global --add safe.directory '*'