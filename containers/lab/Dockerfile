# SPDX-License-Identifier: GPL-2.0-only

FROM ubuntu:24.04@sha256:f610ab94648195aa356059f5b41d6085c9d4d903c072430cdd1af7bdb646106b

ARG MEMENTO_REVISION
ARG MEMENTO_BINARY_SHA256

LABEL org.opencontainers.image.title="memento laboratory runtime" \
      org.opencontainers.image.version="0.1.0-dev" \
      org.opencontainers.image.revision="${MEMENTO_REVISION}" \
      org.opencontainers.image.licenses="GPL-2.0-only" \
      io.memento.binary.sha256="${MEMENTO_BINARY_SHA256}"

COPY --chmod=0755 build/memento /usr/local/bin/memento

RUN test -n "${MEMENTO_REVISION}" \
    && test -n "${MEMENTO_BINARY_SHA256}" \
    && printf '%s  %s\n' "${MEMENTO_BINARY_SHA256}" /usr/local/bin/memento | sha256sum -c -

USER 65532:65532
ENTRYPOINT ["/usr/local/bin/memento"]
