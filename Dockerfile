# syntax=docker/dockerfile:1
#
# Stages:
#   toolchain  compiler, libsodium headers, python3 (for the integration test)
#   build      compiles server and client with -Wall -Wextra -Werror -O2
#   sanitize   AddressSanitizer/UBSan suites built with GCC 14 (GCC 12's
#              ASan can hang on kernels with vm.mmap_rnd_bits=32)
#   test       `docker build --target test .` runs unit and integration
#              suites and requires the sanitize stage to pass
#   runtime    small image with both binaries (default)
#
# libsodium is upstream 1.0.18 in every stage (Debian 12 and Debian 13
# packages of the same release).

ARG DEBIAN_IMAGE=debian:12-slim@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc
ARG GCC14_IMAGE=gcc:14@sha256:a6f425a380ee03e682df3b436fc9077c544fb0fea0a9cab943c3b8320db10765

FROM ${DEBIAN_IMAGE} AS toolchain
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      gcc libc6-dev make pkg-config python3 \
      libsodium-dev=1.0.18-1+deb12u1 \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /src

FROM toolchain AS build
COPY Makefile ./
COPY include include
COPY src src
COPY tests tests
RUN make -j"$(nproc)" all

FROM ${GCC14_IMAGE} AS sanitize
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      pkg-config python3 libsodium-dev=1.0.18-1+deb13u1 \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY Makefile ./
COPY include include
COPY src src
COPY tests tests
RUN gcc --version | head -n 1 \
 && make CC=gcc sanitize \
 && touch /sanitize.passed

FROM build AS test
COPY --from=sanitize /sanitize.passed /tmp/
RUN make check

FROM ${DEBIAN_IMAGE} AS runtime
RUN apt-get update \
 && apt-get install -y --no-install-recommends libsodium23=1.0.18-1+deb12u1 \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --create-home --uid 10001 chat \
 && mkdir -p /data /home/chat/.securechat \
 && chown chat:chat /data /home/chat/.securechat \
 && chmod 0700 /data /home/chat/.securechat
COPY --from=build /src/build/securechat-server /src/build/securechat-client /usr/local/bin/
USER chat
WORKDIR /home/chat
ENV SECURECHAT_KEY=/data/server.key \
    SECURECHAT_HOME=/home/chat/.securechat
VOLUME ["/data"]
EXPOSE 7000
ENTRYPOINT ["securechat-server"]
CMD ["--port", "7000"]
