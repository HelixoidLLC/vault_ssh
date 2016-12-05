/*
 * Copyright 2016 Igor Moochnick
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"golang.org/x/crypto/ssh/terminal"
	"net"
	"os"
	"os/exec"
	"os/user"
	"regexp"
	"runtime"
	"strings"
	"syscall"
	"vault_ssh/certs"
	"vault_ssh/config"
	"vault_ssh/log"
	"vault_ssh/vault"
)

const version = "0.0.3"

var versionFlag bool
var testPassword bool
var asUser string
var withPassword string
var passwdFromEnv bool

func init() {
	runtime.GOMAXPROCS(runtime.NumCPU())

	flag.BoolVar(&versionFlag, "version", false, "prints current version")
	flag.BoolVar(&testPassword, "testpassword", false, "skip asking password")
	flag.StringVar(&asUser, "username", "", "authenticate with Vault using this username")
	flag.StringVar(&withPassword, "password", "", "don't prompt for password and use this one")
	flag.BoolVar(&passwdFromEnv, "pwdenv", false, "read password from environment variable $VAULT_SSH_PWD")
	flag.Parse()
}

// get_ip resolves an IP of a remote host
func get_ip(hostname string) (host_ip string, err error) {
	r, _ := regexp.Compile("^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$")
	is_ip := r.MatchString(hostname)

	host_ip = hostname

	if !is_ip {
		IPAddr, err := net.ResolveIPAddr("ip", hostname)
		if err != nil {
			return "", errors.New("Error in resolving IP")
		}

		addr := net.ParseIP(IPAddr.String())

		if addr == nil {
			return "", errors.New("Invalid address")
		}

		host_ip = addr.String()
	}

	return host_ip, nil
}

// Run will lauch an SSH session/process with the provided credentials against a remote machine
func Run(connectAs string, connectTo string, key string) {
	target := connectAs + "@" + connectTo
	log.Info("Connecting as " + target)

	cmd := exec.Command("/usr/local/bin/sshpass", "-p", key, "ssh", "-t", "-t", target)
	cmd.Stdout = os.Stdout
	cmd.Stdin = os.Stdin
	err := cmd.Start()
	if err != nil {
		log.Fatal(err)
	}
	cmd.Wait()
	log.Infof("Just ran subprocess %d, exiting\n", cmd.Process.Pid)
}

// credentials will be retured by harvesting them from different sources based on the command line-provided parameters
func credentials() (username string, password string) {
	reader := bufio.NewReader(os.Stdin)

	if asUser != "" {
		username = asUser
	} else {
		if currentUser, err := user.Current(); err == nil {
			if testPassword {
				username = "test1"
			} else {
				username = currentUser.Username
				log.Info("Current username: " + username)
			}
		} else {
			fmt.Print("Enter Username: ")
			username, _ = reader.ReadString('\n')
		}
	}

	if testPassword {
		password = "password"
	} else {
		if withPassword != "" {
			password = withPassword
		} else if passwdFromEnv {
			password = os.Getenv("$VAULT_SSH_PWD")
		} else {
			fmt.Print("Enter Password: ")
			bytePassword, err := terminal.ReadPassword(int(syscall.Stdin))
			if err != nil {
				log.Fatalf("Failed to read password")
				os.Exit(-1)
			}
			fmt.Println()
			password = string(bytePassword)
		}
	}

	return strings.TrimSpace(username), strings.TrimSpace(password)
}

func main() {
	if versionFlag {
		fmt.Println(version)
		os.Exit(0)
	}
	if len(flag.Args()) == 0 {
		log.Error("Target to connect wasn't specified")
		os.Exit(-1)
	}
	connectTo := flag.Args()[0]
	connectAs := ""
	var err error

	if strings.Contains(connectTo, "@") {
		s := strings.Split(connectTo, "@")
		connectAs, connectTo = s[0], s[1]
		log.Infof("Connecting to %s as %s", connectTo, connectAs)
		connectTo, err = get_ip(connectTo)
		if err != nil {
			log.Fatalf("Failed to resolve %s", connectTo)
			os.Exit(-1)
		}
	}

	config := config.New()
	config.Url = "https://vault.service.consul:8200"
	config.TlsSkipVerify = true
	config.CaCert = certs.Ca
	config.Cert = certs.Client_cert
	config.CertKey = certs.Client_cert_key

	log.Info("Starting vault_ssh v" + version)
	log.Info("Connecting to Vault at: " + config.Url)

	vault_client, err := vault.Connect(config)
	if err != nil {
		log.Fatal("Failed to connect to Vault")
		os.Exit(-1)
	}

	username, password := credentials()
	log.Infof("Username: %s", username)

	token, err := vault.Login(vault_client, username, password)
	if err != nil {
		os.Exit(-1)
	}
	key, err := vault.Auth(vault_client, token, connectTo, "admin")
	if err != nil {
		os.Exit(-1)
	}

	Run(connectAs, connectTo, key)
}
