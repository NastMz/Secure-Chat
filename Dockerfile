# syntax=docker/dockerfile:1
#
# Stages:
#   toolchain  compiler, libsodium headers, python3 (for the integration test)
#   build      compiles server and client with -Wall -Wextra -Werror -O2
#   test       `docker build --target test .` runs unit, integration and
#              AddressSanitizer/UBSan suites
#   runtime    small image with both binaries (default)

ARG DEBIAN_IMAGE=debian:12-slim@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc

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

FROM build AS test
RUN make check && make sanitize

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
