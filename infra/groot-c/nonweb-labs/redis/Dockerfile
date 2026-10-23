FROM ubuntu@sha256:c664f8f86ed5a386b0a340d981b8f81714e21a8b9c73f658c4bea56aa179d54a
ENV DEBIAN_FRONTEND=noninteractive LC_ALL=C HOME=/tmp PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
COPY . /build
RUN cd /build && sha256sum -c SHA256SUMS >/dev/null \
 && printf '#!/bin/sh\nexit 101\n' > /usr/sbin/policy-rc.d && chmod 0755 /usr/sbin/policy-rc.d \
 && for deb in /build/debs/*.deb; do name="$(dpkg-deb -f "$deb" Package)"; version="$(dpkg-deb -f "$deb" Version | sed 's/:/%3a/g')"; arch="$(dpkg-deb -f "$deb" Architecture)"; cp "$deb" "/var/cache/apt/archives/${name}_${version}_${arch}.deb"; done \
 && apt-get --no-download --no-install-recommends -y install /build/debs/*.deb \
 && test -z "$(dpkg --audit)" \
 && test "$(dpkg-query -W -f='${Version}' redis-server)" = '5:5.0.7-2' \
 && groupadd -g 10001 lab-terminal \
 && useradd -u 10001 -g 10001 -d /tmp -M -s /bin/sh lab-terminal \
 && mkdir -p /lab /etc/redis /var/lib/redis \
 && cp /build/*.sh /lab/ && cp /build/provenance.json /lab/ \
 && cp /build/redis.conf /etc/redis/lab.conf \
 && chmod 0555 /lab/*.sh && chmod 0444 /lab/provenance.json /etc/redis/lab.conf \
 && rm -rf /build /var/lib/apt/lists/* /var/cache/apt/archives/*
LABEL io.capstone.nonweb-lab="redis" io.capstone.cve="CVE-2022-0543" io.capstone.software-version="5.0.7" io.capstone.package-version="5:5.0.7-2"
USER 65534:65534
WORKDIR /tmp
ENTRYPOINT ["/lab/start.sh"]
