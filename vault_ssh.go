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
	"path/filepath"
	"io/ioutil"
)

const version = "0.0.11"
const vault_token_file_name = "/.vault-token"

var versionFlag bool
var testPassword bool
var asUser string
var withPassword string
var passwdFromEnv bool
var environment string

func init() {
	runtime.GOMAXPROCS(runtime.NumCPU())

	flag.BoolVar(&versionFlag, "version", false, "prints current version")
	flag.BoolVar(&testPassword, "testpassword", false, "skip asking password")
	flag.StringVar(&asUser, "username", "", "authenticate with Vault using this username")
	flag.StringVar(&withPassword, "password", "", "don't prompt for password and use this one")
	flag.BoolVar(&passwdFromEnv, "pwdenv", false, "read password from environment variable $VAULT_SSH_PWD")
	flag.StringVar(&environment, "env", "dev", "ID of an environment (i.e.: dev, stg, prod) defaults to dev")
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

	executable := "sshpass"
	params := []string{
		"-p", key, "ssh", "-o", "StrictHostKeyChecking=no", "-t", "-t", target,
	}
	log.Infof("Launching: %s %s", executable, strings.Join(params, " "))

	if log.GetLevel() == log.DebugLevel {
		for i, param := range params {
			if param == "ssh" {
				i = i + 1
				// Yes: this is crazy, but this inserts an element into a slice
				params = append(params[:i], append([]string{"-v"}, params[i:]...)...)
				break
			}
		}
	}

	cmd := exec.Command(executable, params...)
	cmd.Stderr = os.Stderr
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
	log.Info("Connecting with username: " + username)

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
	environments := map[string]interface{}{"dev": nil, "stg": nil, "prod": nil}
	if _, ok := environments[environment]; !ok {
		log.Errorf("Specified environment value '%s' is invalid.", environment)
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
	config.Url = "https://vault.service.consul.csdops.net:8200"
	config.TlsSkipVerify = true
	config.CaCert = certs.Certs[environment+"_Ca"]
	config.Cert = certs.Certs[environment+"_Client_cert"]
	config.CertKey = certs.Certs[environment+"_Client_cert_key"]

	log.Info("Starting vault_ssh v" + version)
	log.Info("Connecting to Vault at: " + config.Url)

	vault_client, err := vault.Connect(config)
	if err != nil {
		log.Fatal("Failed to connect to Vault")
		os.Exit(-1)
	}

	token := os.Getenv("VAULT_TOKEN")
	if token == "" {
		usr, _ := user.Current()
		dir := usr.HomeDir
		vault_token_file := filepath.Join(dir, vault_token_file_name)

		if asUser == "" {
			token, err = get_token(vault_token_file)
			if err != nil {
				log.Fatal("Failed to detect token")
				os.Exit(-1)
			}
			if token != "" {
				// Trying to re-use previously saved token
				log.Info("Trying token from " + vault_token_file)
				ttl, err := vault.CheckToken(vault_client, token)
				if err != nil {
					token = ""
				}
				if ttl != nil {
					log.Infof("Token expires in %s", ttl.String())
				}
			} else {
				log.Debug("Didn't find " + vault_token_file)
			}
		}
		if token == "" {
			log.Info("VAULT_TOKEN not set. Asking for credentials ...")

			username, password := credentials()

			token, err = vault.Login(vault_client, username, password)
			if err != nil {
				os.Exit(-1)
			}

			if err == nil {
				log.Infof("Saving Vault token to " + vault_token_file)
				err = ioutil.WriteFile(vault_token_file, []byte(token), 0644)
				if err != nil {
					log.Error("Failed to write token file: %s", err)
				}
			}
		}
	} else {
		log.Info("Using token from VAULT_TOKEN environment variable")
	}
	if token != "" {
		key, err := vault.RequestOTP(vault_client, connectTo, connectAs)
		if err != nil {
			os.Exit(-1)
		}

		Run(connectAs, connectTo, key)
	}
}

func get_token(vault_token_file string) (string, error) {
	token := ""

	usr, _ := user.Current()
	dir := usr.HomeDir
	old_vault_token_file := filepath.Join(dir, ".vault")
	fi, err := os.Stat(old_vault_token_file)
	if err == nil {
		/*
			if fi.Mode().IsDir() {
				log.Warningf("Detected %s to be a directory. Removing ...", old_vault_token_file)
				err := os.RemoveAll(old_vault_token_file)
				if err != nil {
					log.Errorf("Failed to remove folder %s", old_vault_token_file)
					return "", err
				}
			} else {
				log.Warningf("Detected %s to be a file. Removing ...", old_vault_token_file)
				err := os.RemoveAll(old_vault_token_file)
				if err != nil {
					log.Errorf("Failed to remove folder %s", old_vault_token_file)
					return "", err
				}
			}
		*/
		log.Warningf("Detected %s present. Removing ...", old_vault_token_file)
		err := os.RemoveAll(old_vault_token_file)
		if err != nil {
			log.Errorf("Failed to remove %s", old_vault_token_file)
			return "", err
		}
	}

	fi, err = os.Stat(vault_token_file)
	if err != nil {
		// file doesn't exist
		return "", nil
	} else {
		if fi.Mode().IsDir() {
			log.Warningf("Detected %s to be a directory. Removing ...", vault_token_file)
			err := os.RemoveAll(vault_token_file)
			if err != nil {
				log.Errorf("Failed to remove folder %s", vault_token_file)
				return "", err
			}
		}
	}

	if _, err = os.Stat(vault_token_file); err == nil {
		log.Debug("Found file: " + vault_token_file)
		data, err := ioutil.ReadFile(vault_token_file)
		if err != nil {
			log.Error("Failed to read token from file. " + err.Error())
			return "", err
		} else {
			token = string(data)
			log.Debug("Loaded token: " + token)
			return token, nil
		}
	}
	return "", nil
}
