FROM bobowski/talos/base

SHELL ["/bin/bash", "-c"]


ADD Makefile /tmp/Makefile
ADD nginx.conf /tmp/nginx.conf


RUN buildDeps='build-essential wget ca-certificates pkg-config git make \
  libpcre3-dev gcc avr-libc zlib1g-dev bison flex libtool openssh-client \
  patch libapr1-dev libaprutil1-dev' \
    && set -x \
    && apt-get update && apt-get install -y $buildDeps --no-install-recommends \
    && cd /tmp/ \
    && wget http://nginx.org/download/nginx-1.11.0.tar.gz \
    && tar -xzf nginx-1.11.0.tar.gz \
    && cd /tmp/nginx-1.11.0 \
    && ./configure --prefix=/opt/nginx-1.11.0/ --with-http_ssl_module --with-openssl=/opt/talos \
    && cp /tmp/Makefile /tmp/nginx-1.11.0/objs/Makefile \
    && make \
    && make install \
    && cp /tmp/nginx.conf /opt/nginx-1.11.0/conf/ \
    && cd /opt/nginx-1.11.0/conf \
    && echo -ne "\n\n\n\n\n\n\n" | openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout cert.key -out cert.crt \
    && cd /opt/nginx-1.11.0/sbin && ln -sfn /opt/talos/lib/enclave.signed.so . \
    && rm -rf /tmp/* \
    && apt-get purge -y --auto-remove $buildDeps \
    && apt-get install -y libssl-dev \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean \
    && apt-get autoclean
