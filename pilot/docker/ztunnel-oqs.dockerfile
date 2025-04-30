# Define build arguments for version tags, installation paths, and configurations.
#ARG ALPINE_VERSION=3.21
ARG OPENSSL_TAG=openssl-3.4.0
ARG LIBOQS_TAG=0.12.0
ARG OQSPROVIDER_TAG=0.8.0
ARG INSTALLDIR=/opt/oqssa

# Specify supported signature and key encapsulation mechanisms (KEM) algorithms.
ARG SIG_ALG="dilithium3"
ARG DEFAULT_GROUPS="x25519:x448:kyber512:p256_kyber512:kyber768:p384_kyber768:kyber1024:p521_kyber1024"


# Stage 1: Build - Compile and assemble all necessary components and dependencies.
#FROM alpine:${ALPINE_VERSION} AS intermediate
FROM fedora:41

ARG OPENSSL_TAG
ARG LIBOQS_TAG
ARG OQSPROVIDER_TAG
ARG INSTALLDIR
ARG SIG_ALG
ARG DEFAULT_GROUPS

LABEL version="6"

# Install required build tools and system dependencies.
RUN dnf -y update && dnf -y install \
    @development-tools \
    make cmake ninja-build autoconf automake libtool \
    openssl openssl-devel \
    iptables \
    git && \
    dnf clean all

# Download and prepare source files needed for the build process.
WORKDIR /opt
RUN git clone --depth 1 --branch ${LIBOQS_TAG} https://github.com/open-quantum-safe/liboqs && \
    git clone --depth 1 --branch ${OPENSSL_TAG} https://github.com/openssl/openssl.git && \
    git clone --depth 1 --branch ${OQSPROVIDER_TAG} https://github.com/open-quantum-safe/oqs-provider.git

# Build and install liboqs
WORKDIR /opt/liboqs/build
RUN cmake -G"Ninja" .. \
          -DOQS_DIST_BUILD=ON \
          -DCMAKE_INSTALL_PREFIX="${INSTALLDIR}" && \
    ninja install

# Build and install OpenSSL, then configure symbolic links.
WORKDIR /opt/openssl
RUN dnf -y install perl perl-FindBin
RUN if [ -d "${INSTALLDIR}/lib64" ]; then ln -s "${INSTALLDIR}/lib64" "${INSTALLDIR}/lib"; fi && \
    if [ -d "${INSTALLDIR}/lib" ]; then ln -s "${INSTALLDIR}/lib" "${INSTALLDIR}/lib64"; fi && \
    LDFLAGS="-Wl,-rpath -Wl,${INSTALLDIR}/lib64" ./config shared --prefix="${INSTALLDIR}" && \
    make -j"$(nproc)" && make install_sw install_ssldirs;

# Set PATH for custom OpenSSL binary.
ENV PATH="${INSTALLDIR}/bin:${PATH}"

# Build, install, and configure the oqs-provider for OpenSSL integration.
WORKDIR /opt/oqs-provider
RUN ln -s ../openssl . && \
    cmake -DOPENSSL_ROOT_DIR="${INSTALLDIR}" \
          -DCMAKE_BUILD_TYPE=Release \
          -DCMAKE_PREFIX_PATH="${INSTALLDIR}" \
          -S . -B _build && \
    cmake --build _build && \
    cp _build/lib/oqsprovider.so "${INSTALLDIR}/lib64/ossl-modules" && \
    sed -i "s/default = default_sect/default = default_sect\noqsprovider = oqsprovider_sect/g" ${INSTALLDIR}/ssl/openssl.cnf && \
    sed -i "s/\[default_sect\]/\[default_sect\]\nactivate = 1\n\[oqsprovider_sect\]\nactivate = 1\n/g" ${INSTALLDIR}/ssl/openssl.cnf && \
    sed -i "s/providers = provider_sect/providers = provider_sect\nssl_conf = ssl_sect\n\n\[ssl_sect\]\nsystem_default = system_default_sect\n\n\[system_default_sect\]\nGroups = \$ENV\:\:DEFAULT_GROUPS\n/g" ${INSTALLDIR}/ssl/openssl.cnf && \
    sed -i "s/\# Use this in order to automatically load providers/\# Set default KEM groups if not set via environment variable\nKDEFAULT_GROUPS = $DEFAULT_GROUPS\n\n# Use this in order to automatically load providers/g" ${INSTALLDIR}/ssl/openssl.cnf && \
    sed -i "s/HOME\t\t\t= ./HOME\t\t= .\nDEFAULT_GROUPS\t= ${DEFAULT_GROUPS}/g" ${INSTALLDIR}/ssl/openssl.cnf

RUN mkdir -p /usr/lib64/ossl-modules && ln -s /opt/oqssa/lib64/ossl-modules/oqsprovider.so /usr/lib64/ossl-modules/oqsprovider.so
RUN export LD_LIBRARY_PATH=/opt/oqssa/lib:/opt/oqssa/lib64:$LD_LIBRARY_PATH

COPY ztunnel /usr/local/bin/ztunnel
COPY pilot/docker/entrypoint.sh /usr/local/bin/entrypoint.sh

WORKDIR /

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]

