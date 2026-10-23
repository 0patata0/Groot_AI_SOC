FROM ubuntu@sha256:c664f8f86ed5a386b0a340d981b8f81714e21a8b9c73f658c4bea56aa179d54a AS build
ENV DEBIAN_FRONTEND=noninteractive LC_ALL=C PYTHON=/usr/bin/python2
COPY . /build
RUN cd /build && sha256sum -c SHA256SUMS >/dev/null \
 && printf '#!/bin/sh\nexit 101\n' > /usr/sbin/policy-rc.d && chmod 0755 /usr/sbin/policy-rc.d \
 && for deb in /build/debs/*.deb; do name="$(dpkg-deb -f "$deb" Package)"; version="$(dpkg-deb -f "$deb" Version | sed 's/:/%3a/g')"; arch="$(dpkg-deb -f "$deb" Architecture)"; cp "$deb" "/var/cache/apt/archives/${name}_${version}_${arch}.deb"; done \
 && apt-get --no-download --no-install-recommends -y install /build/debs/*.deb \
 && test -z "$(dpkg --audit)" \
 && ln -s /usr/bin/python2 /usr/local/bin/python \
 && tar -xf /build/samba-4.6.3.tar -C /build \
 && cd /build/samba-4.6.3 \
 && ./configure --prefix=/usr/local/samba --without-ad-dc --without-ads --without-ldap --without-pam --disable-cups --disable-iprint --disable-avahi --without-regedit --without-libarchive \
 && make -j2 && make install \
 && test "$(/usr/local/samba/sbin/smbd --version)" = 'Version 4.6.3'
FROM ubuntu@sha256:c664f8f86ed5a386b0a340d981b8f81714e21a8b9c73f658c4bea56aa179d54a
ENV DEBIAN_FRONTEND=noninteractive LC_ALL=C HOME=/tmp PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
COPY --from=build /usr/local/samba /usr/local/samba
COPY . /build
RUN cd /build && sha256sum -c SHA256SUMS >/dev/null \
 && printf '#!/bin/sh\nexit 101\n' > /usr/sbin/policy-rc.d && chmod 0755 /usr/sbin/policy-rc.d \
 && for deb in /build/runtime-debs/*.deb; do name="$(dpkg-deb -f "$deb" Package)"; version="$(dpkg-deb -f "$deb" Version | sed 's/:/%3a/g')"; arch="$(dpkg-deb -f "$deb" Architecture)"; cp "$deb" "/var/cache/apt/archives/${name}_${version}_${arch}.deb"; done \
 && apt-get --no-download --no-install-recommends -y install /build/runtime-debs/*.deb \
 && test -z "$(dpkg --audit)" \
 && groupadd -g 10001 lab-terminal \
 && useradd -u 10001 -g 10001 -d /tmp -M -s /bin/sh lab-terminal \
 && ln -s /usr/local/samba/sbin/smbd /usr/sbin/smbd \
 && ln -s /usr/local/samba/bin/smbclient /usr/bin/smbclient \
 && ldd /usr/sbin/smbd /usr/bin/smbclient > /tmp/samba-ldd \
 && ! grep -q 'not found' /tmp/samba-ldd \
 && mkdir -p /lab /etc/samba /run/samba /var/lib/samba /var/cache/samba /var/log/samba /share \
 && cp /build/*.sh /lab/ && cp /build/provenance.json /lab/ \
 && cp /build/smb.conf /etc/samba/smb.conf \
 && mkdir -p /usr/local/samba/etc \
 && ln -s /etc/samba/smb.conf /usr/local/samba/etc/smb.conf \
 && chmod 0555 /lab/*.sh && chmod 0444 /lab/provenance.json /etc/samba/smb.conf \
 && /usr/local/samba/bin/testparm -s /etc/samba/smb.conf >/dev/null \
 && rm -rf /build /tmp/samba-ldd /var/lib/apt/lists/* /var/cache/apt/archives/*
LABEL io.capstone.nonweb-lab="samba" io.capstone.cve="CVE-2017-7494" io.capstone.software-version="4.6.3" io.capstone.package-version="source-4.6.3"
USER 0:0
WORKDIR /tmp
ENTRYPOINT ["/lab/start.sh"]
