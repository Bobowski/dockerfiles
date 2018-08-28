FROM bobowski/talos/nginx

SHELL ["/bin/bash", "-c"]


ARG SGX_MODE=SIM

RUN buildDeps='build-essential wget ca-certificates pkg-config git make' \
    && set -x \
    && apt-get update && apt-get install -y $buildDeps --no-install-recommends \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean \
    && apt-get autoclean \
    && cd /tmp \
    && git clone https://github.com/intel/intel-sgx-ssl.git \
    && cd intel-sgx-ssl/openssl_source/ \
    && wget https://www.openssl.org/source/openssl-1.1.0g.tar.gz \
    && cd /tmp/intel-sgx-ssl/Linux \
    && source /opt/intel/sgxsdk/environment \
    && make all test SGX_MODE=${SGX_MODE} \
    && make install SGX_MODE=${SGX_MODE} \
    && rm -rf /tmp/* \
    && apt-get purge -y --auto-remove $buildDeps

RUN apt-get update && apt-get install -y build-essential python3 python3-pip

RUN echo "source /opt/intel/sgxsdk/environment" >> /root/.bashrc
RUN echo "export LD_LIBRARY_PATH=${LD_LIBRARY_PATH}:/opt/talos/lib/" >> /root/.bashrc

ADD nginx.conf /opt/nginx-1.11.0/conf/nginx.conf
