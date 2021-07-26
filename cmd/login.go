package cmd

import (
	"bytes"
	"compress/flate"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	uuid "github.com/google/uuid"
	sig "github.com/russellhaering/goxmldsig"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

const (
	AUTHN_REQ_TEMPL = `<?xml version="1.0"?>
<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{{.Id}}" Version="2.0" IssueInstant="{{.ZuluStartTime}}" AssertionConsumerServiceURL="{{.Endpoint}}" Destination="{{.Destination}}">
	<saml:Issuer>{{.EntityId}}</saml:Issuer>
	<samlp:NameIDPolicy AllowCreate="true" Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"/>
</samlp:AuthnRequest>`
	CREDENTIALS_FILENAME = "ksamlauth.credentials"
)

type GlobalConfigSection struct {
	Port          int    `toml:"port"`
	Endpoint      string `toml:"endpoint"`
	EntityId      string `toml:"entity_id"`
	MyPrivateKey  string `toml:"my_key"`
	MyCertificate string `toml:"my_certificate"`
}

type Configuration struct {
	Global GlobalConfigSection `toml:"global"`
}

func generateQueryString(request string) string {
	urlenc := make(url.Values)
	urlenc["SAMLRequest"] = []string{request}
	saml_request_enc := urlenc.Encode()
	urlenc = make(url.Values)
	urlenc["RelayState"] = []string{"token"}
	relay_state_enc := urlenc.Encode()
	urlenc = make(url.Values)
	urlenc["SigAlg"] = []string{"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"}
	sig_alg_enc := urlenc.Encode()
	result := fmt.Sprintf("%s&%s&%s", saml_request_enc, relay_state_enc, sig_alg_enc)
	log.Debug("Query string to sign: ", result)
	return result
}

func getSamlDeflectedSignature(params, key, cert string) (string, error) {
	loaded_cert, err := tls.X509KeyPair([]byte(cert), []byte(key))
	if err != nil {
		return "", err
	}
	memKeyStore := sig.TLSCertKeyStore(loaded_cert)
	sign_ctx := sig.NewDefaultSigningContext(&memKeyStore)
	err = sign_ctx.SetSignatureMethod(sig.RSASHA256SignatureMethod)
	if err != nil {
		return "", err
	}
	signature, err := sign_ctx.SignString(params)
	if err != nil {
		return "", err
	}
	result := base64.StdEncoding.EncodeToString(signature)
	log.Debug("Signature: ", result)
	urlenc := make(url.Values)
	urlenc["Signature"] = []string{result}
	return urlenc.Encode(), nil
}

func createSamlAuthnRequest(endpoint, entity, destination string, lvl int) (string, error) {
	reqid := uuid.New()
	time_bt, err := time.Now().UTC().MarshalText()
	if err != nil {
		return "", err
	}
	xmlstr := strings.Replace(AUTHN_REQ_TEMPL, "{{.Id}}", reqid.String(), -1)
	xmlstr = strings.Replace(xmlstr, "{{.ZuluStartTime}}", string(time_bt), -1)
	xmlstr = strings.Replace(xmlstr, "{{.Endpoint}}", endpoint, -1)
	xmlstr = strings.Replace(xmlstr, "{{.EntityId}}", entity, -1)
	xmlstr = strings.Replace(xmlstr, "{{.Destination}}", destination, -1)
	log.Debug("AuthnRequest XML: ", xmlstr)

	bfr := new(bytes.Buffer)
	flate_wr, err := flate.NewWriter(bfr, lvl)
	if err != nil {
		return "", err
	}
	n, err := flate_wr.Write([]byte(xmlstr))
	if err != nil {
		flate_wr.Close()
		return "", err
	}
	if n != len(xmlstr) {
		flate_wr.Close()
		return "", fmt.Errorf("wrong amount of bytes written %d <> %d", n, len(xmlstr))
	}
	flate_wr.Close()
	log.Debug("Deflated AuthnRequest XML: ", base64.StdEncoding.EncodeToString(bfr.Bytes()))
	return base64.StdEncoding.EncodeToString(bfr.Bytes()), nil
}

type IdPResponseHandler struct {
	CredentialsPath string
	ExitChannel     chan string
}

func (ip *IdPResponseHandler) WriteMsg(w http.ResponseWriter, message string, statusCode int) {
	w.WriteHeader(statusCode)
	status_message := "Success!"
	if statusCode > 299 {
		status_message = "ERROR"
	}
	html_message := fmt.Sprintf(`<html>
<head>
<title>KSAMLAuth Endpoint</title>
</head>
<body>
<h1>%s</h1><br>
%s
</body>
</html>`, status_message, message)
	w.Write([]byte(html_message))
}

func (ip *IdPResponseHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	respBody, err := ioutil.ReadAll(r.Body)
	if err != nil {
		ip.WriteMsg(w, "Something went wrong, please check the console for more information", 500)
		log.Fatal(err)
		return
	}
	respBodyStr := string(respBody)
	log.Debug("IdP response: ", respBodyStr)
	vals, err := url.ParseQuery(respBodyStr)
	if err != nil {
		ip.WriteMsg(w, "Something went wrong, please check the console for more information", 500)
		log.Fatal(err)
		return
	}
	if itms, ok := vals["SAMLResponse"]; !ok {
		ip.WriteMsg(w, "Something went wrong, please check the console for more information", 500)
		log.Fatal(fmt.Errorf("no SAMLResponse field in the IdP response"))
		return
	} else {
		err := ioutil.WriteFile(ip.CredentialsPath, []byte(fmt.Sprintf("SAMLResponse=%s", itms[0])), 0644)
		if err != nil {
			ip.WriteMsg(w, "Something went wrong, please check the console for more information", 500)
			log.Fatal(err)
			return
		}
	}
	ip.WriteMsg(w, "Authentication credentials stored, you may close this window now", 200)
	ip.ExitChannel <- "done"
}

func readConfigFile(path string, conf *Configuration) error {
	_, err := toml.DecodeFile(path, conf)
	if err != nil {
		return err
	}
	if (*conf).Global.Endpoint == "" {
		return fmt.Errorf("configuration file error: endpoint may not be empty")
	}
	_, err = url.Parse((*conf).Global.Endpoint)
	if err != nil {
		return fmt.Errorf("configuration file error: endpoint error: %s", err)
	}
	if (*conf).Global.EntityId == "" {
		return fmt.Errorf("configuration file error: entity_id may not be empty")
	}
	return err
}

func generateDefaultConfigFile(path string) error {
	defconf := Configuration{
		Global: GlobalConfigSection{
			Port:     16160,
			Endpoint: "https://url.to.idp/endpoint",
			EntityId: "entitiy-or-client-id-as-per-IdP",
			MyCertificate: `-----BEGIN CERTIFICATE-----
my own certificate data comes in here
-----END CERTIFICATE-----`,
			MyPrivateKey: `-----BEGIN RSA PRIVATE KEY-----
my own private key data comes in here
-----END RSA PRIVATE KEY-----`,
		},
	}
	fh, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer fh.Close()
	enc := toml.NewEncoder(fh)
	err = enc.Encode(&defconf)
	return err
}

var loginCmd = &cobra.Command{
	Use:   "login",
	Short: "login performs SAML2.0 authentication against an identity provider",
	Long: `This part of the program performs SAML2.0 based authentication against
an identity provider, by preparing the authentication request and giving you
a URI to copy and paste into your browser. In the background an HTTP server
is started, which listens for successful authentication and receives then
the response from the identity provider. The data is then stored as credentials,
which later can be used to confirm the identity against the kubernetes cluster.`,
	Run: func(cmd *cobra.Command, args []string) {
		if enableDebug, err := cmd.Flags().GetBool("debug"); err != nil {
			log.Fatal(err)
			return
		} else if enableDebug {
			log.SetLevel(log.DebugLevel)
		}
		var conf_file_path string
		var folder_flag string
		if conf_flag, err := cmd.Flags().GetString("conf"); err == nil {
			if folder_flag, err = cmd.Flags().GetString("kube-folder"); err == nil {
				conf_file_path = path.Join(folder_flag, conf_flag)
			} else {
				log.Fatal(err)
				return
			}
		} else {
			log.Fatal(err)
			return
		}
		if dogen, err := cmd.Flags().GetBool("generate-default-config"); err != nil {
			log.Fatal(err)
			return
		} else if dogen {
			err := generateDefaultConfigFile(conf_file_path)
			if err != nil {
				log.Fatal(err)
			}
			return
		}
		var app_config Configuration
		err := readConfigFile(conf_file_path, &app_config)
		if err != nil {
			log.Fatal(err)
			return
		}
		b64xml, err := createSamlAuthnRequest(fmt.Sprintf("http://localhost:%d/endpoint", app_config.Global.Port), app_config.Global.EntityId, app_config.Global.Endpoint, 9)
		if err != nil {
			log.Fatal(err)
			return
		}
		string_to_sign := generateQueryString(b64xml)
		signature, err := getSamlDeflectedSignature(string_to_sign, app_config.Global.MyPrivateKey, app_config.Global.MyCertificate)
		if err != nil {
			log.Fatal(err)
			return
		}
		exit_channel := make(chan string)
		ip := IdPResponseHandler{
			CredentialsPath: path.Join(folder_flag, CREDENTIALS_FILENAME),
			ExitChannel:     exit_channel,
		}
		http.Handle("/endpoint", &ip)
		go func() {
			log.Fatal(http.ListenAndServe(fmt.Sprintf("127.0.0.1:%d", app_config.Global.Port), nil))
		}()

		log.Printf("Please, copy and paste the following URI in your browser:\n%s?%s&%s", app_config.Global.Endpoint, string_to_sign, signature)

		<-exit_channel
		time.Sleep(1 * time.Second)
		os.Exit(0)
	},
}

func init() {
	loginCmd.Flags().String("conf", "ksamlauth.toml", "specify an alternative filename for the ksamlauth config file")
	loginCmd.Flags().String("kube-folder", path.Join(os.Getenv("HOME"), ".kube"), "specify an alternative path for the .kube folder")
	loginCmd.Flags().Bool("generate-default-config", false, "generate a default config TOML file and exit")
}
