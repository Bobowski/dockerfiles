FROM ubuntu:16.04
MAINTAINER Adam Bobowski <bobowski.adam@gmail.com>

COPY ./patches /patches

RUN buildDeps='build-essential ocaml automake autoconf libtool wget \
libssl-dev libcurl4-openssl-dev protobuf-compiler protobuf-c-compiler libprotobuf-dev \
git patch python python3 python3-pip' \
    && set -x \
    && apt-get update && apt-get install -y $buildDeps --no-install-recommends \
    && apt-get install -y openssl \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean \
    && apt-get autoclean \
    && cd /tmp \
    && git clone --branch sgx_2.1 https://github.com/01org/linux-sgx.git \
    && cd / \
    && for patch in /patches/*; do patch --prefix=/patches/ -p0 --force "--input=$patch" || exit 1; done \
    && rm -rf /patches \
    && cd /tmp/linux-sgx \
    && ./download_prebuilt.sh \
    && make \
    && make sdk_install_pkg \
    && make psw_install_pkg \
    && mkdir -p /opt/intel \
    && cd /opt/intel \
    && yes yes | /tmp/linux-sgx/linux/installer/bin/sgx_linux_x64_sdk_*.bin \
    && /tmp/linux-sgx/linux/installer/bin/sgx_linux_x64_psw_*.bin \
    && rm -rf /tmp/* \
    && rm -rf /patches \
    && apt-get purge -y --auto-remove $buildDeps
