test:
	go test -v ./...

integration:
	go test -v --tags=integration ./...

build:
	rm -rf bin
	mkdir -p bin/mac
	GOOS=darwin GOARCH=386 go build -o=bin/mac/vault_ssh
	chmod +x bin/mac/vault_ssh
	mkdir -p bin/linux
	GOOS=linux GOARCH=386 go build -o=bin/linux/vault_ssh
	chmod +x bin/linux/vault_ssh
#	GOOS=darwin GOARCH=amd64 go build -o=bin/vault_ssh_mac_amd64
#	GOOS=linux GOARCH=amd64 go build -o=bin/vault_ssh_linux_amd64
#   CGO_ENABLED=0 GOOS=darwin go build -a -installsuffix cgo -o vault_ssh_mac vault_ssh.go

bump:
	gobump patch -w
