# Stage 1: Minimal rootfs builder (optional)
FROM quay.io/fedora/fedora-bootc:42 as builder
RUN /usr/libexec/bootc-base-imagectl build-rootfs --manifest=minimal /target-rootfs

# Stage 2: Full-feature image
FROM quay.io/fedora/fedora-bootc:42

# Install packages
RUN dnf -y install \
    qemu-guest-agent \
    openssh-server \
    NetworkManager \
    yum-utils && \
    dnf config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo && \
    dnf install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin && \
    dnf clean all

# Enable services (active only when run with systemd)
RUN systemctl enable qemu-guest-agent && \
    systemctl enable docker && \
    systemctl enable podman-auto-update.timer

# Copy container systemd unit
COPY caddy.container /usr/share/containers/systemd/

# Copy auth config link config
COPY containers-auth.conf /usr/lib/tmpfiles.d/link-podman-credentials.conf

LABEL containers.bootc=1
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
