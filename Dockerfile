FROM golang:1.5.3

RUN apt-get update
RUN apt-get install -y libpcap-dev
COPY . /go/src/github.com/remind101/dnsdog
RUN GO15VENDOREXPERIMENT=1 go install github.com/remind101/dnsdog/cmd/...
