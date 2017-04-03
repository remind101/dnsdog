FROM golang:1.7.0

RUN apt-get update
RUN apt-get install -y libpcap-dev
COPY . /go/src/github.com/remind101/dnsdog
RUN go install github.com/remind101/dnsdog/cmd/...
