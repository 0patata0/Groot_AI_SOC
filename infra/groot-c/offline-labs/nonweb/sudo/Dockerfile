# Build only with the context produced by prepare.py. No network/package fetch.
FROM ubuntu@sha256:c664f8f86ed5a386b0a340d981b8f81714e21a8b9c73f658c4bea56aa179d54a
ARG SUDO_DEB_SHA256
ARG PREPARATION_SHA256
COPY sudo.deb /tmp/sudo.deb
COPY preparation.json /lab/preparation.json
COPY check.sh /lab/check.sh
RUN test "$(dpkg --print-architecture)" = amd64 \
 && test -n "$SUDO_DEB_SHA256" && test -n "$PREPARATION_SHA256" \
 && printf '%s  /tmp/sudo.deb\n' "$SUDO_DEB_SHA256" | sha256sum -c - \
 && printf '%s  /lab/preparation.json\n' "$PREPARATION_SHA256" | sha256sum -c - \
 && dpkg -i /tmp/sudo.deb \
 && test -z "$(dpkg --audit)" \
 && groupadd --gid 1000 lab \
 && useradd --uid 1000 --gid 1000 --no-create-home --home-dir /tmp --shell /bin/sh lab \
 && chmod 0555 /lab/check.sh \
 && /lab/check.sh \
 && rm /tmp/sudo.deb
LABEL io.capstone.sudo-lab="1" \
      io.capstone.sudo-lab.package-version="1.8.31-1ubuntu1" \
      io.capstone.sudo-lab.base="sha256:c664f8f86ed5a386b0a340d981b8f81714e21a8b9c73f658c4bea56aa179d54a" \
      io.capstone.sudo-lab.deb-sha256="$SUDO_DEB_SHA256" \
      io.capstone.sudo-lab.preparation-sha256="$PREPARATION_SHA256"
USER 1000:1000
ENV LC_ALL=C HOME=/tmp PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
WORKDIR /tmp
ENTRYPOINT ["/usr/bin/sleep"]
CMD ["infinity"]
