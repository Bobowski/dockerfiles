FROM ubuntu:16.04
MAINTAINER Adam Bobowski <bobowski.adam@gmail.com>


ARG SGX_SDK_FILE="sgx_linux_x64_sdk_2.2.100.45311.bin"
ARG SGX_BIN_URL="https://download.01.org/intel-sgx/linux-2.2/ubuntu64-desktop"
ARG SGX_DOWNLOAD_URL="${SGX_BIN_URL}/${SGX_SDK_FILE}"

RUN buildDeps='wget ca-certificates make' \
    && set -x \
    && apt-get update && apt-get install -y $buildDeps --no-install-recommends \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean \
    && apt-get autoclean \
    && mkdir /opt/intel \
    && cd /opt/intel \
    && wget ${SGX_DOWNLOAD_URL} \
    && chmod +x ${SGX_SDK_FILE} \
    && echo "yes" | ./${SGX_SDK_FILE} \
    && rm ${SGX_SDK_FILE} \
    && apt-get purge -y --auto-remove $buildDeps
