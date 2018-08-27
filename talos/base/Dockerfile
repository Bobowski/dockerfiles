FROM bobowski/intel-sgx/base

SHELL ["/bin/bash", "-c"]

ADD logpoint.c /tmp/logpoint.c


RUN buildDeps='build-essential wget ca-certificates pkg-config git make \
  libpcre3-dev gcc avr-libc zlib1g-dev bison flex libtool openssh-client \
  patch libapr1-dev libaprutil1-dev' \
    && set -x \
    && apt-get update && apt-get install -y $buildDeps --no-install-recommends \
    && apt-get install -y libssl-dev \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean \
    && apt-get autoclean \
    && cd / \
    && git clone --single-branch -b tls-processing https://github.com/Bobowski/TaLoS.git \
    && cp /tmp/logpoint.c /TaLoS/src/talos/enclaveshim/logpoint.c \
    && cd /TaLoS/src/talos \
    && ./patch_libressl.sh \
    && cd /TaLoS/src/libressl-2.4.1/crypto \
    && source /opt/intel/sgxsdk/environment \
    && make -f Makefile.sgx SGX_MODE=SIM \
    && make -f Makefile.sgx install SGX_MODE=SIM \
    && mkdir -p /opt/talos \
    && cd /opt/talos \
    && mkdir lib include bin \
    && cp -r /TaLoS/src/libressl-2.4.1/include/* ./include \
    && cp -r /TaLoS/src/libressl-2.4.1/crypto/libenclave.a ./bin \
    && cp -r /TaLoS/src/libressl-2.4.1/crypto/libenclave.so ./bin \
    && cp -r /TaLoS/src/libressl-2.4.1/crypto/enclave.signed.so ./bin \
    && ln -sfn /opt/talos/bin/enclave.signed.so lib/enclave.signed.so \
    && ln -sfn /opt/talos/bin/libenclave.a lib/libcrypto.a \
    && ln -sfn /opt/talos/bin/libenclave.a lib/libssl.a \
    && ln -sfn /opt/talos/bin/libenclave.so lib/libcrypto.so \
    && ln -sfn /opt/talos/bin/libenclave.so lib/libssl.so \
    && rm -rf /TaLoS \
    && apt-get purge -y --auto-remove $buildDeps
