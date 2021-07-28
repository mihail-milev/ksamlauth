
all: container

container: build
	cd buildah && buildah unshare ./build.sh && cd ..

build:
	GOPATH=${GOPATH} go get .
	CGO_ENABLED=0 GOPATH=${GOPATH} GOOS=linux GOARCH=amd64 go build -o ksamlauth
	CGO_ENABLED=0 GOPATH=${GOPATH} GOOS=windows GOARCH=amd64 go build -o ksamlauth-win
	CGO_ENABLED=0 GOPATH=${GOPATH} GOOS=darwin GOARCH=amd64 go build -o ksamlauth-mac

clean:
	rm -f ./ksamlauth

.PHONY: all build container clean