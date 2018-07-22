FROM ubuntu:16.04
MAINTAINER Adam Bobowski <bobowski.adam@gmail.com>


ARG SGX_SDK_FILE="sgx_linux_x64_sdk_2.2.100.45311.bin"
ARG SGX_DOWNLOAD_URL="https://download.01.org/intel-sgx/linux-2.2/ubuntu64-desktop/${SGX_SDK_FILE}"

RUN apt-get update && apt-get install -y --no-install-recommends \
    wget \
    ca-certificates \
    make \
  && apt-get clean \
  && apt-get autoclean \
  && rm -rf /var/lib/apt/lists/*

RUN mkdir /opt/intel \
  &&  cd /opt/intel \
  && wget ${SGX_DOWNLOAD_URL} \
  && chmod +x ${SGX_SDK_FILE} \
  && echo "yes" | ./${SGX_SDK_FILE} \
  && rm ${SGX_SDK_FILE}
