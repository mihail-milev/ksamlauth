package cmd

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"path"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

const (
	VALIDATE_LOG_FILENAME = "ksamlauth-validate.log"
)

type ExecCredentialStatus struct {
	Token string `json:"token"`
}

type ExecCredentialStruct struct {
	Status ExecCredentialStatus `json:"status"`
}

func sendDataToKsamlauthDaemon(dt []byte, endpoint *url.URL, token_only, insecure_skip_tls_verify bool) error {
	br := bytes.NewReader(dt)
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: insecure_skip_tls_verify,
			},
		},
	}
	req, err := http.NewRequest("POST", endpoint.String(), br)
	if err != nil {
		return err
	}
	req.Header.Add("Content-Type", "multipart/form-data")
	req.Header.Add("Content-Length", fmt.Sprintf("%d", len(dt)))
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode > 299 {
		return fmt.Errorf("HTTP (%d): %s", resp.StatusCode, string(respBody))
	}
	if token_only {
		var exec_cred ExecCredentialStruct
		err = json.Unmarshal(respBody, &exec_cred)
		if err != nil {
			return err
		}
		fmt.Println(exec_cred.Status.Token)
	} else {
		fmt.Println(string(respBody))
	}
	return nil
}

func writeErrorToLogfile(fpath string, gerr error) {
	fh, err := os.OpenFile(fpath, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		log.Fatal(err)
		return
	}
	defer fh.Close()
	written, err := fh.WriteString(gerr.Error())
	if err != nil {
		log.Fatal(err)
		return
	}
	if written != len(gerr.Error()) {
		log.Fatalf("Error length not fully written: %d <> %d\n", written, len(gerr.Error()))
		return
	}
	fh.WriteString("\n")
}

var validateCmd = &cobra.Command{
	Use:   "validate",
	Short: "validate sends the saved SAML reponse to the ksamlauth daemon in a specific cluster",
	Long: fmt.Sprintf(`This part of the program gets the data stored inside %s
and sends it over to the ksamlauth daemon endpoint inside the target
cluster over a POST request. If an error happens, then the error
is stored inside %s.`, CREDENTIALS_FILENAME, VALIDATE_LOG_FILENAME),
	Run: func(cmd *cobra.Command, args []string) {
		kube_folder, err := cmd.Flags().GetString("kube-folder")
		if err != nil {
			kube_folder = path.Join(os.Getenv("HOME"), ".kube")
		}
		log_path := path.Join(kube_folder, VALIDATE_LOG_FILENAME)
		if len(args) < 1 {
			writeErrorToLogfile(log_path, fmt.Errorf("%s", cmd.UsageString()))
			os.Exit(-1)
		}
		endpoint, err := url.Parse(args[0])
		if err != nil {
			writeErrorToLogfile(log_path, err)
			os.Exit(-1)
		}
		token_only, err := cmd.Flags().GetBool("token-only")
		if err != nil {
			writeErrorToLogfile(log_path, err)
			os.Exit(-1)
		}
		insecure_skip_tls_verify, err := cmd.Flags().GetBool("insecure-skip-tls-verify")
		if err != nil {
			writeErrorToLogfile(log_path, err)
			os.Exit(-1)
		}
		post_data, err := ioutil.ReadFile(path.Join(kube_folder, CREDENTIALS_FILENAME))
		if err != nil {
			writeErrorToLogfile(log_path, err)
			os.Exit(-1)
		}
		err = sendDataToKsamlauthDaemon(post_data, endpoint, token_only, insecure_skip_tls_verify)
		if err != nil {
			writeErrorToLogfile(log_path, err)
			os.Exit(-1)
		}
	},
}

func init() {
	def_kube_folder := path.Join(os.Getenv("HOME"), ".kube")
	validateCmd.Flags().String("kube-folder", def_kube_folder, "specify an alternative path for the .kube folder")
	validateCmd.Flags().Bool("token-only", false, "if set, instead of the JSON structure, only the SA token will be printed to the console on success")
	validateCmd.Flags().Bool("insecure-skip-tls-verify", false, "if set, the validation towards the ksamlauth daemon ingress will not verify the certificate")
	validateCmd.SetUsageTemplate(fmt.Sprintf(`Usage:
  ksamlauth validate [flags] {ksamlauth-endpoint-url}

Flags:
  -h, --help                      help for validate
      --kube-folder string        specify an alternative path for the .kube folder (default "%s")
      --token-only                if set, instead of the JSON structure, only the SA token will be printed to the console on success
      --insecure-skip-tls-verify  if set, the validation towards the ksamlauth daemon ingress will not verify the certificate

Global Flags:
      --debug   enable debug messages

`, def_kube_folder))
}
