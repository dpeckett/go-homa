VERSION 0.7
FROM golang:1.21-bookworm
WORKDIR /workspace

tidy:
  LOCALLY
  RUN go mod tidy
  RUN go fmt ./...

lint:
  FROM golangci/golangci-lint:v1.55.2
  WORKDIR /workspace
  COPY . ./
  RUN golangci-lint run --timeout 5m ./...

test:
  COPY . ./
  RUN go test -coverprofile=coverage.out -v ./...
  SAVE ARTIFACT ./coverage.out AS LOCAL coverage.out

# For the github runner, we need to install the kernel module.
load-kmod:
  FROM ubuntu:22.04
  WORKDIR /workspace
  RUN apt update
  RUN apt install -y kmod git build-essential linux-headers-$(uname -r)
  RUN git clone --depth=1 https://github.com/PlatformLab/HomaModule.git
  WORKDIR /workspace/HomaModule
  RUN make
  RUN make install
  RUN --privileged insmod /lib/modules/$(uname -r)/extra/homa.ko

