############################################################
# Dockerfile to build NIST-BGP-SRx container images
# Based on CentOS 7
############################################################
#FROM centos:latest
FROM centos:7
ENV container docker


################## BEGIN INSTALLATION ######################
RUN yum -y install epel-release
RUN yum -y install wget libconfig libconfig-devel openssl openssl-devel libcrypto.so.* telnet less gcc screen net-tools nano
RUN yum -y install uthash-devel net-snmp readline-devel patch git net-snmp-config net-snmp-devel automake rpm-build autoconf libtool
RUN wget https://dl.google.com/go/go1.13.linux-amd64.tar.gz
RUN tar -C /usr/local -xzf go1.13.linux-amd64.tar.gz
RUN rm go1.13.linux-amd64.tar.gz

ENV GOROOT /usr/local/go
ENV GOPATH /go
ENV PATH $GOPATH/bin:$GOROOT/bin:$PATH

COPY . /root/
ENTRYPOINT ./start_gobgp.sh

# KeyVolt configuration
RUN mkdir -p /usr/opt/bgp-srx-examples/bgpsec-keys/
VOLUME ["/usr/opt/bgp-srx-examples/bgpsec-keys/"]


# SRxCryptoAPI configuration

WORKDIR /root/srx-crypto-api
RUN autoreconf -i
RUN ./configure --prefix=/usr CFLAGS="-O0 -g"
RUN make all install && ldconfig


WORKDIR /root/srx-server
RUN autoreconf -i
RUN ./configure --prefix=/usr sca_dir=/usr --cache-file=/dev/null --srcdir=.
RUN make all install && ldconfig


WORKDIR /root/quagga-srx
RUN autoreconf -i
RUN ./configure --prefix=/usr --disable-snmp --disable-ospfapi --disable-ospfd --disable-ospf6d \
    --disable-babeld --disable-doc --disable-tests --enable-user=root --enable-group=root \
    --enable-configfile-mask=0644 --enable-logfile-mask=0644 \
    --enable-srxcryptoapi sca_dir=/usr srx_dir=/usr
RUN make all install && ldconfig


# GoBGPSRx configuration
WORKDIR /root/gobgpsrx
RUN export CGO_LDFLAGS="-L/root/local-6.2.0/lib64/srx/ -Wl,-rpath -Wl,/root/local-6.2.0/lib64/srx/"
RUN go install ./...


# SRxCryptoAPI post scripts
WORKDIR /root
RUN /bin/cp -rf examples/bgpsec-keys /usr/opt/bgp-srx-examples/ \
        && /bin/cp -rf quagga-srx/bgpd/bgpd.conf.sampleSRx /usr/etc/bgpd.conf \
        && rm -rf /etc/ld.so.cache && ldconfig


EXPOSE 2605 179 17900 17901 323
CMD ["sleep", "infinity"]


############# DOCKER RUN command example #####################################
# docker run -ti \
#       -p 179:179 -p 17900:17900 -p 17901:17901 -p 2605:2605 -p 323:323 \
#       -v $PWD/examples/bgpsec-keys/:/usr/opt/bgp-srx-examples/bgpsec-keys/ \
#       <docker_image> [command]
##############################################################################