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

package vault

import (
	"github.com/hashicorp/go-cleanhttp"
	"net/url"
	"os"
	"strings"

	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	vaultapi "github.com/hashicorp/vault/api"
	"net"
	"net/http"
	"vault_ssh/config"
	"vault_ssh/log"
	"time"
)

// TLSConfig is used to generate a TLSClientConfig that's useful for talking to
// Consul using TLS.
type TLSConfig struct {
	// Address is the optional address of the Consul server. The port, if any
	// will be removed from here and this will be set to the ServerName of the
	// resulting config.
	Address string

	// CAFile is the optional path to the CA certificate used for Consul
	// communication, defaults to the system bundle if not specified.
	CAFile string

	// CertFile is the optional path to the certificate for Consul
	// communication. If this is set then you need to also set KeyFile.
	CertFile string

	// KeyFile is the optional path to the private key for Consul communication.
	// If this is set then you need to also set CertFile.
	KeyFile string

	// InsecureSkipVerify if set to true will disable TLS host verification.
	InsecureSkipVerify bool
}

func Connect(config config.Config) (client *vaultapi.Client, err error) {

	address := config.Url
	if address == "" {
		address = os.Getenv("VAULT_ADDR")
	}
	if address == "" {
		log.Fatal("Can't find address of a Vault server")
		return nil, errors.New("Can't find address of a Vault server")
	}

	_vaultClient, err := createClient(address, config.CaCert, config.Cert, config.CertKey, config.TlsSkipVerify)

	return _vaultClient, nil
}

func createClient(address string, CaCert string, Cert string, CertKey string, TlsSkipVerify bool) (*vaultapi.Client, error) {
	config := vaultapi.DefaultConfig()
	config.Address = address

	u, err := url.Parse(address)
	if err != nil {
		return nil, err
	}
	if u.Scheme == "https" {
		config.HttpClient.Transport = createTlsTransport(CaCert, Cert, CertKey, TlsSkipVerify)
	} else {
		log.Debug("Created non-TLS client")
	}

	client, err := vaultapi.NewClient(config)

	return client, err
}

func createTlsTransport(CaCert string, Cert string, CertKey string, TlsSkipVerify bool) http.RoundTripper {

	//tlsClientConfig, err := SetupTLSConfig(&TLSConfig{
	//	InsecureSkipVerify: TlsSkipVerify,
	//	CAFile:             CaFile,
	//	CertFile:           CertFile,
	//	KeyFile:            KeyFile,
	//})

	tlsClientConfig, err := SetupTLSConfig(CaCert, Cert, CertKey, TlsSkipVerify)

	// We don't expect this to fail given that we aren't
	// parsing any of the input, but we panic just in case
	// since this doesn't have an error return.
	if err != nil {
		panic(err)
	}

	transport := cleanhttp.DefaultPooledTransport()
	transport.TLSClientConfig = tlsClientConfig
	transport.TLSClientConfig.InsecureSkipVerify = true
	return transport
}

// TLSConfig is used to generate a TLSClientConfig that's useful for talking to Consul using TLS.
func SetupTLSConfig(CaCert string, Cert string, CertKey string, TlsSkipVerify bool) (*tls.Config, error) {
	tlsClientConfig := &tls.Config{
		InsecureSkipVerify: TlsSkipVerify,
	}

	tlsAddress := ""
	if tlsAddress != "" {
		server := tlsAddress
		hasPort := strings.LastIndex(server, ":") > strings.LastIndex(server, "]")
		if hasPort {
			var err error
			server, _, err = net.SplitHostPort(server)
			if err != nil {
				return nil, err
			}
		}
		tlsClientConfig.ServerName = server
	}

	if Cert != "" && CertKey != "" {
		tlsCert, err := LoadX509KeyPair(Cert, CertKey)
		if err != nil {
			return nil, err
		}
		tlsClientConfig.Certificates = []tls.Certificate{tlsCert}
	}

	if CaCert != "" {
		//data, err := ioutil.ReadFile(tlsConfig.CAFile)
		//if err != nil {
		//	return nil, fmt.Errorf("failed to read CA file: %v", err)
		//}
		data := []byte(Cert)

		caPool := x509.NewCertPool()
		if !caPool.AppendCertsFromPEM(data) {
			return nil, fmt.Errorf("failed to parse CA certificate")
		}
		tlsClientConfig.RootCAs = caPool
	}

	return tlsClientConfig, nil
}

func LoadX509KeyPair(cert, cert_key string) (tls.Certificate, error) {
	//certPEMBlock, err := ioutil.ReadFile(certFile)
	certPEMBlock := []byte(cert)
	//if err != nil {
	//	return tls.Certificate{}, err
	//}
	//keyPEMBlock, err := ioutil.ReadFile(keyFile)
	keyPEMBlock := []byte(cert_key)
	//if err != nil {
	//	return tls.Certificate{}, err
	//}
	return tls.X509KeyPair(certPEMBlock, keyPEMBlock)
}

func TrimSuffix(s, suffix string) string {
	if strings.HasSuffix(s, suffix) {
		s = s[:len(s)-len(suffix)]
	}
	return s
}

func Login(vault *vaultapi.Client, username string, password string) (string, error) {
	data := map[string]interface{}{
		"password": password,
	}
	path := fmt.Sprintf("auth/ldap/login/%s", username)
	secret, err := vault.Logical().Write(path, data)
	if err != nil {
		log.Fatalf("Failed to write to vault: %#v", err)
		return "", errors.New("Failed to write to vault")
	}
	log.Debugf("Got secret: %#v", secret)
	log.Info("Preserve login token by setting: export VAULT_TOKEN=" + secret.Auth.ClientToken)
	vault.SetToken(secret.Auth.ClientToken)
	return secret.Auth.ClientToken, nil
}

// RequestOTP is called to retreive a One-time-Password for SSH access
func RequestOTP(vault *vaultapi.Client, ip string, username string) (key string, err error) {
	data := map[string]interface{}{
		"ip":       ip,
		"username": username,
	}
	secret, err := vault.Logical().Write("ssh/creds/otp_key_role", data)
	if err != nil {
		log.Error("Make sure your VAULT_TOKEN didn't expire")
		log.Fatalf("Failed to write to vault: %#v", err)
		return "", errors.New("Failed to write to vault")
	}
	log.Debugf("Got secret: %#v", secret)
	key_i := secret.Data["key"]
	key = key_i.(string)
	return key, nil
}

func CheckToken(vault *vaultapi.Client, token string) (*time.Duration, error) {
	vault.SetToken(token)
	secret, err := vault.Logical().Read("auth/token/lookup-self")
	if err != nil {
		log.Error("Failed to get information from Vault about specified token: " + token)
		log.Error(err)
		return nil, err
	}
	log.Debugf("Got secret: %#v", secret)
	data := secret.Data
	ttlStr := getStringFromMap(&data, "ttl", "")
	log.Debug("TTL: " + ttlStr)
	if ttlStr != "" {
		ttl, err := time.ParseDuration(ttlStr + "s")
		if err != nil {
			log.Error("Failed to parse ttl")
			return nil, err
		}

		return &ttl, nil
	}

	return nil, nil
}