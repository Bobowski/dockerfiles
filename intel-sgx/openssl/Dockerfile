FROM intel-sgx/linux

SHELL ["/bin/bash", "-c"]

ARG SGX_MODE=SIM

# Install requirements
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    pkg-config \
    git \
    make \
  && apt-get clean \
  && apt-get autoclean \
  && rm -rf /var/lib/apt/lists/*

# Download intel-sgx-openssl and openssl
RUN cd /tmp && \
  git clone https://github.com/intel/intel-sgx-ssl.git && \
  cd intel-sgx-ssl/openssl_source/ && \
  wget https://www.openssl.org/source/openssl-1.1.0g.tar.gz

# Build
RUN cd /tmp/intel-sgx-ssl/Linux && \
   source /opt/intel/sgxsdk/environment && \
   make all test SGX_MODE=${SGX_MODE} && \
   make install SGX_MODE=${SGX_MODE}

# Remove temporary files
RUN rm -rf /tmp/*
