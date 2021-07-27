
all: container

container: build
	cd buildah && buildah unshare ./build.sh && cd ..

build:
	GOPATH=${GOPATH} go get .
	CGO_ENABLED=0 GOPATH=${GOPATH} go build

clean:
	rm -f ./ksamlauth

.PHONY: all build container clean