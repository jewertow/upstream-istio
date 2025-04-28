FROM fedora:41

RUN dnf install -y openssl oqsprovider iptables

COPY ztunnel /usr/local/bin/ztunnel

ENTRYPOINT ["/usr/local/bin/ztunnel"]
