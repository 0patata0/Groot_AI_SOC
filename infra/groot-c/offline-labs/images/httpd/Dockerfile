# Build on the approved Linux/amd64 builder; no package installation is needed.
ARG HTTPD_BASE_IMAGE=docker.io/library/httpd@sha256:4b5cb7697fea2aa6d398504c381b693a54ae9ad5e6317fcdbb7a2d9b8c3b1364
FROM ${HTTPD_BASE_IMAGE}
ARG HTTPD_BASE_IMAGE

LABEL org.opencontainers.image.title="Groot Apache HTTP Server file-access lab" \
      org.opencontainers.image.description="Isolated static-file lab; CGI disabled; contains only public training fixtures" \
      io.capstone.lab.family="apache-httpd-path-normalization"

# Bare config-digest IDs are only for a verified classic image store/builder.
# Containerd image stores use the canonical manifest reference above.
# Refuse an unreviewed base reference or version mismatch before creating the lab.
RUN set -eu; \
    case "$HTTPD_BASE_IMAGE" in \
      sha256:e91425f386186eb981e47f90780083cc2a16179f3ec45581fa7e5ba044b800fb|docker.io/library/httpd@sha256:4b5cb7697fea2aa6d398504c381b693a54ae9ad5e6317fcdbb7a2d9b8c3b1364) expected=2.4.49 ;; \
      sha256:bc9d3c5a7455df2d13d9093f31aaeda04adf4726b2f8a462f4669e9b67330c79|docker.io/library/httpd@sha256:a0a1605656b89fe249c6306e5646d3d3c2d50606e134d411d8e8f732527cbdbb) expected=2.4.50 ;; \
      *) echo 'Unreviewed HTTPD_BASE_IMAGE' >&2; exit 1 ;; \
    esac; \
    test "$HTTPD_VERSION" = "$expected"; \
    httpd -v | grep -F "Server version: Apache/$expected "; \
    mkdir -p /lab/www /lab/public /lab/fixture

COPY --chown=0:0 httpd.conf /usr/local/apache2/conf/httpd.conf
COPY --chown=0:0 site/ /lab/www/
COPY --chown=0:0 public/ /lab/public/
COPY --chown=0:0 fixture/ /lab/fixture/

RUN set -eu; \
    case "$HTTPD_VERSION" in \
      2.4.49) lab_cve=CVE-2021-41773 ;; \
      2.4.50) lab_cve=CVE-2021-42013 ;; \
      *) echo 'Unsupported HTTPD_VERSION' >&2; exit 1 ;; \
    esac; \
    sed -i "s/@@HTTPD_VERSION@@/$HTTPD_VERSION/g; s/@@CVE_ID@@/$lab_cve/g" /lab/www/index.html; \
    printf '{"software":"Apache HTTP Server","version":"%s","cve_id":"%s","cgi_enabled":false,"fixture":"/lab/fixture/harmless.txt"}\n' \
      "$HTTPD_VERSION" "$lab_cve" > /lab/www/version.json; \
    printf 'groot-httpd-lab-ok\n' > /lab/www/health.txt; \
    chmod 0755 /lab /lab/www /lab/public /lab/fixture; \
    chmod 0644 /usr/local/apache2/conf/httpd.conf /lab/www/* /lab/public/* /lab/fixture/*

USER 65532:65532
WORKDIR /usr/local/apache2
EXPOSE 8080
HEALTHCHECK NONE
# Do not use the upstream helper, which removes a PID file under ServerRoot.
CMD ["httpd", "-DFOREGROUND", "-f", "/usr/local/apache2/conf/httpd.conf"]
