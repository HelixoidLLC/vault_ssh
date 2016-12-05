test:
	go test -v ./...

integration:
	go test -v --tags=integration ./...

build:
	GOOS=darwin GOARCH=386 go build -o=bin/vault_ssh_mac
	chmod +x bin/vault_ssh_mac
	GOOS=linux GOARCH=386 go build -o=bin/vault_ssh_linux
	chmod +x bin/vault_ssh_linux
#	GOOS=darwin GOARCH=amd64 go build -o=bin/vault_ssh_mac_amd64
#	GOOS=linux GOARCH=amd64 go build -o=bin/vault_ssh_linux_amd64
#   CGO_ENABLED=0 GOOS=darwin go build -a -installsuffix cgo -o vault_ssh_mac vault_ssh.go

bump:
	gobump patch -w
