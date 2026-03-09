FROM ubuntu:24.04

# Avoid tzdata interactive prompt
ENV DEBIAN_FRONTEND=noninteractive

RUN apt update && apt install -y \
    curl \
    python3 \
    python3-pip \
    jq \
    unzip \
    && rm -rf /var/lib/apt/lists/*

# Install Google Cloud CLI
RUN curl -O https://dl.google.com/dl/cloudsdk/channels/rapid/downloads/google-cloud-cli-linux-x86_64.tar.gz \
    && tar -xf google-cloud-cli-linux-x86_64.tar.gz \
    && ./google-cloud-sdk/install.sh --quiet \
    && rm google-cloud-cli-linux-x86_64.tar.gz

ENV PATH=$PATH:/google-cloud-sdk/bin

# Setup Workdir
WORKDIR /attacks

# Copy all scripts to the container
COPY scripts/ /attacks/scripts/
COPY menu.sh /attacks/menu.sh

# Make sure shell scripts are executable
RUN chmod +x /attacks/scripts/*.sh /attacks/menu.sh

ENTRYPOINT ["/attacks/menu.sh"]
