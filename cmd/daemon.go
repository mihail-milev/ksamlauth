package cmd

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"path"
	"strconv"
	"strings"
	"time"

	"ksamlauth/k8s"

	"github.com/beevik/etree"
	sig "github.com/russellhaering/goxmldsig"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

const (
	ENV_VAR_NAME_TOKEN_DIR             = "KUBERNETES_SERVICE_ACCOUNT_TOKEN_DIR"
	ENV_VAR_SA_NAMESPACE               = "NAMESPACE_FOR_MANAGING_SA"
	ENV_VAR_LISTEN_PORT                = "KSAMLAUTH_LISTEN_PORT"
	ENV_VAR_IDP_CERT                   = "IDP_CERTIFICATE"
	DEFAULT_LISTEN_PORT                = 16161
	ANNOTATION_TITLE_MODIFICATION_TIME = "ksamlauth/modification-time"
	ANNOTATION_TITLE_IN_RESPONSE_TO    = "ksamlauth/in-response-to"
	DEFAULT_TOKEN_VALID_PERIOD         = 30 * time.Minute
	DEFAULT_SA_PRUNE_PERIOD            = 5 * time.Second
	ENV_VAR_KUBERNETES_ENDPOINT        = "CUSTOM_KUBERNETES_ENDPOINT"
	ENV_VAR_USERCONFIG                 = "KSAMLAUTH_USERCONFIG"
)

type KubernetesSAInfo struct {
	Cert  string
	Token string
}

type JsonErrorResponse struct {
	Error string `json:"error"`
}

type JsonSuccessResponseStatus struct {
	ExpirationTimestamp string `json:"expirationTimestamp"`
	Token               string `json:"token"`
}

type JsonSuccessResponse struct {
	Kind       string                    `json:"kind"`
	ApiVersion string                    `json:"apiVersion"`
	Spec       struct{}                  `json:"spec"`
	Status     JsonSuccessResponseStatus `json:"status"`
}

type ValidateHandler struct {
	K8sConfig   *KubernetesSAInfo
	Certificate *x509.Certificate
	K8sEndpoint string
}

func (vh *ValidateHandler) performAdditionalResponseChecks(validated_xml string) (string, time.Time, string, error) {
	doc := etree.NewDocument()
	err := doc.ReadFromString(validated_xml)
	if err != nil {
		return "", time.Now(), "", err
	}
	root_elem := doc.Root()
	status_code_elem := root_elem.FindElement("/Response/Status/StatusCode")
	if status_code_elem == nil {
		return "", time.Now(), "", fmt.Errorf("status code subelement not found")
	}
	status_code_attr := status_code_elem.SelectAttr("Value")
	if status_code_attr == nil {
		return "", time.Now(), "", fmt.Errorf("status code attribute not found")
	}
	if status_code_attr.Value != "urn:oasis:names:tc:SAML:2.0:status:Success" {
		return "", time.Now(), "", fmt.Errorf("status code is not Success")
	}

	conditions_elem := root_elem.FindElement("/Response/Assertion/Conditions")
	if conditions_elem == nil {
		return "", time.Now(), "", fmt.Errorf("conditions subelement not found")
	}
	notbefore_attr := conditions_elem.SelectAttr("NotBefore")
	if notbefore_attr == nil {
		return "", time.Now(), "", fmt.Errorf("conditions 'not before' attribute not found")
	}
	notonorafter_attr := conditions_elem.SelectAttr("NotOnOrAfter")
	if notonorafter_attr == nil {
		return "", time.Now(), "", fmt.Errorf("conditions 'not on or after' attribute not found")
	}
	notbefore, err := time.Parse(time.RFC3339, notbefore_attr.Value)
	if err != nil {
		return "", time.Now(), "", err
	}
	notonorafter, err := time.Parse(time.RFC3339, notonorafter_attr.Value)
	if err != nil {
		return "", time.Now(), "", err
	}
	current_utc_time := time.Now().UTC()
	if current_utc_time.Unix() < notbefore.Unix() {
		cur_time_str, err := current_utc_time.MarshalText()
		if err != nil {
			return "", time.Now(), "", err
		}
		return "", time.Now(), "", fmt.Errorf("current time %s is not after %s", string(cur_time_str), notbefore_attr.Value)
	}

	subject_conf_elem := root_elem.FindElement("/Response/Assertion/Subject/SubjectConfirmation/SubjectConfirmationData")
	if subject_conf_elem == nil {
		return "", time.Now(), "", fmt.Errorf("subject confirmation data subelement not found")
	}
	inresp_to_attr := subject_conf_elem.SelectAttr("InResponseTo")
	if inresp_to_attr == nil {
		return "", time.Now(), "", fmt.Errorf("in response to attribute not found")
	}

	username_elem := root_elem.FindElement("/Response/Assertion/Subject/NameID")
	if username_elem == nil {
		return "", time.Now(), "", fmt.Errorf("nameid subelement not found")
	}

	return username_elem.Text(), notonorafter, inresp_to_attr.Value, nil
}

func (vh *ValidateHandler) validateSamlResponse(saml_response string) (string, error) {
	decoded, err := base64.StdEncoding.DecodeString(saml_response)
	if err != nil {
		return "", err
	}
	doc := etree.NewDocument()
	err = doc.ReadFromBytes(decoded)
	if err != nil {
		return "", err
	}
	vc := sig.NewDefaultValidationContext(&sig.MemoryX509CertificateStore{
		Roots: []*x509.Certificate{vh.Certificate},
	})
	validated, err := vc.Validate(doc.Root())
	if err != nil {
		return "", err
	}
	newdoc := etree.NewDocument()
	newdoc.SetRoot(validated)
	return newdoc.WriteToString()
}

func (vh *ValidateHandler) WriteErrResponse(w http.ResponseWriter, message string, statusCode int) {
	msg := JsonErrorResponse{
		Error: message,
	}
	dt, err := json.Marshal(&msg)
	if err != nil {
		log.Error(err)
		return
	}
	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	w.Write(dt)
}

func (vh *ValidateHandler) WriteSuccessResponse(w http.ResponseWriter, message, token_expiration_time string) {
	msg := JsonSuccessResponse{
		Kind:       "ExecCredential",
		ApiVersion: "client.authentication.k8s.io/v1alpha1",
		Status: JsonSuccessResponseStatus{
			Token:               message,
			ExpirationTimestamp: token_expiration_time,
		},
	}
	dt, err := json.Marshal(&msg)
	if err != nil {
		log.Error(err)
		return
	}
	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(200)
	w.Write(dt)
}

func (vh *ValidateHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	bodydt, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Error(err)
	}
	bodyStr := strings.ReplaceAll(string(bodydt), "+", "%2B")
	vals, err := url.ParseQuery(bodyStr)
	if err != nil {
		vh.WriteErrResponse(w, "Request not in POST multipart/www-urlencoded form", 400)
		log.Error(err)
		return
	}
	saml_response := ""
	if itms, ok := vals["SAMLResponse"]; !ok {
		vh.WriteErrResponse(w, "Request doesn't contain a valid SAMLResponse", 400)
		log.Error(fmt.Errorf("no SAMLResponse field in the IdP response: %s", bodyStr))
		return
	} else {
		saml_response = itms[0]
	}
	newxml, err := vh.validateSamlResponse(saml_response)
	if err != nil {
		vh.WriteErrResponse(w, fmt.Sprintf("SAML validation error: %s", err), 400)
		log.Error(err)
		return
	}
	log.Debug("Validated XML: ", newxml)
	username, notonorafter, in_resp_to, err := vh.performAdditionalResponseChecks(newxml)
	if err != nil {
		vh.WriteErrResponse(w, fmt.Sprintf("SAML validation error: %s", err), 400)
		log.Error(err)
		return
	}
	// search for account with username
	pm, _ := pem.Decode([]byte(vh.K8sConfig.Cert))
	k8scert, err := x509.ParseCertificate(pm.Bytes)
	if err != nil {
		log.Fatalf("validator: parse cert error: %s", err)
		return
	}
	k8s_conn := k8s.NewK8sConnection(&vh.K8sConfig.Token, k8scert, vh.K8sEndpoint)
	current_utc_time := time.Now().UTC()
	current_time_str, err := current_utc_time.MarshalText()
	if err != nil {
		vh.WriteErrResponse(w, "Something went wrong while converting current time", 500)
		log.Error(err)
		return
	}
	sa_found, err := k8s_conn.SearchForSa(username, os.Getenv(ENV_VAR_SA_NAMESPACE))
	if err != nil && fmt.Sprintf("%s", err) != k8s.NOT_FOUND_ERROR {
		vh.WriteErrResponse(w, "Something went wrong while getting service account list", 500)
		log.Error(err)
		return
	} else if fmt.Sprintf("%s", err) == k8s.NOT_FOUND_ERROR {
		// if not existing -> check time and create
		if current_utc_time.Unix() >= notonorafter.Unix() {
			noton_time_str, err := notonorafter.MarshalText()
			if err != nil {
				vh.WriteErrResponse(w, "Something went wrong while converting NotOn time", 500)
				log.Error(err)
				return
			}
			vh.WriteErrResponse(w, "The SAML response is outdated, please re-login", 400)
			log.Errorf("SAML response has the NotOnOrBefore=%s, current time is %s\n", string(noton_time_str), string(current_time_str))
			return
		}
		annotations := map[string]string{
			ANNOTATION_TITLE_MODIFICATION_TIME: string(current_time_str),
			ANNOTATION_TITLE_IN_RESPONSE_TO:    in_resp_to,
		}
		err = k8s_conn.CreateSa(username, os.Getenv(ENV_VAR_SA_NAMESPACE), annotations)
		if err != nil {
			vh.WriteErrResponse(w, "Unable to create SA", 500)
			log.Error(err)
			return
		}
		time.Sleep(1 * time.Second) // give k8s some time to create the token
	} else {
		// if existing -> check time and update
		mod_timestamp_str, mod_timestamp_exists := sa_found.Metadata.Annotations[ANNOTATION_TITLE_MODIFICATION_TIME]
		if !mod_timestamp_exists {
			vh.WriteErrResponse(w, "SA doesn't have a creation timestamp", 500)
			log.Error(err)
			return
		}
		mod_timestamp, err := time.Parse(time.RFC3339, mod_timestamp_str)
		if err != nil {
			vh.WriteErrResponse(w, "unable to convert creation timestamp", 500)
			log.Error(err)
			return
		}
		mod_timestamp_plus_30min := mod_timestamp.Add(DEFAULT_TOKEN_VALID_PERIOD)
		if mod_timestamp_plus_30min.Unix() < current_utc_time.Unix() {
			err = k8s_conn.DeleteSa(username, os.Getenv(ENV_VAR_SA_NAMESPACE))
			if err != nil {
				vh.WriteErrResponse(w, "unable to delete SA", 500)
				log.Error(err)
				return
			}
			vh.WriteErrResponse(w, "The token validity time has passed away, please re-login", 400)
			log.Errorf("Creation time stamp = %s, current time is %s\n", mod_timestamp_str, string(current_time_str))
			return
		}
		in_response_to, in_response_to_exists := sa_found.Metadata.Annotations[ANNOTATION_TITLE_IN_RESPONSE_TO]
		if !in_response_to_exists {
			vh.WriteErrResponse(w, "SA doesn't have a in response to field", 500)
			log.Error(err)
			return
		}
		if in_response_to != in_resp_to {
			err = k8s_conn.DeleteSa(username, os.Getenv(ENV_VAR_SA_NAMESPACE))
			if err != nil {
				vh.WriteErrResponse(w, "unable to delete SA", 500)
				log.Error(err)
				return
			}
			vh.WriteErrResponse(w, "The SA has another in response to field, please re-login", 400)
			log.Errorf("SA in response to = %s, SAML response to = %s\n", in_response_to, in_resp_to)
			return
		}
		annotations := map[string]string{
			ANNOTATION_TITLE_MODIFICATION_TIME: string(current_time_str),
			ANNOTATION_TITLE_IN_RESPONSE_TO:    in_resp_to,
		}
		err = k8s_conn.PatchSaAnnotations(sa_found.Metadata.Name, sa_found.Metadata.Namespace, annotations)
		if err != nil {
			vh.WriteErrResponse(w, "unable to patch SA", 500)
			log.Error(err)
			return
		}
	}
	current_utc_time_plus_30min := current_utc_time.Add(DEFAULT_TOKEN_VALID_PERIOD)
	token_expiration_time_dt, err := current_utc_time_plus_30min.MarshalText()
	if err != nil {
		vh.WriteErrResponse(w, "Something went wrong while converting token validity time", 500)
		log.Error(err)
		return
	}
	token_to_return, err := k8s_conn.GetTokenForSa(username, os.Getenv(ENV_VAR_SA_NAMESPACE))
	if err != nil {
		vh.WriteErrResponse(w, "Unable to get token", 500)
		log.Error(err)
		return
	}
	vh.WriteSuccessResponse(w, token_to_return, string(token_expiration_time_dt))
}

func saPruner(k8sconfig *KubernetesSAInfo, k8sendpoint string) {
	c := time.Tick(DEFAULT_SA_PRUNE_PERIOD)
	pm, _ := pem.Decode([]byte((*k8sconfig).Cert))
	cert, err := x509.ParseCertificate(pm.Bytes)
	if err != nil {
		log.Fatalf("SA pruner: parse cert error: %s", err)
		return
	}
	k8s_conn := k8s.NewK8sConnection(&(*k8sconfig).Token, cert, k8sendpoint)
	for range c {
		log.Debug("SA pruner running ...")
		sa_in_ns, err := k8s_conn.GetAllSAinNamespace(os.Getenv(ENV_VAR_SA_NAMESPACE))
		if err != nil {
			log.Error(err)
			continue
		}
		for _, sa := range sa_in_ns.Items {
			log.Debugf("SA pruner: checking SA %s", sa.Metadata.Name)
			time_annotation, time_annotation_exists := sa.Metadata.Annotations[ANNOTATION_TITLE_MODIFICATION_TIME]
			if !time_annotation_exists {
				continue
			}
			log.Debugf("SA pruner: found time annotation %s", time_annotation)
			modtime, err := time.Parse(time.RFC3339, time_annotation)
			if err != nil {
				log.Error(err)
				continue
			}
			delete_time := modtime.Add(DEFAULT_TOKEN_VALID_PERIOD)
			curtime := time.Now().UTC()
			if delete_time.Unix() < curtime.Unix() {
				log.Debugf("SA pruner: deleting SA %s, because to be deleted time=%s and curtime=%s", sa.Metadata.Name, delete_time, curtime)
				err = k8s_conn.DeleteSa(sa.Metadata.Name, sa.Metadata.Namespace)
				if err != nil {
					log.Error(err)
					continue
				}
			}
		}
		sa_in_ns = nil
	}
}

func writeDownloadError(w http.ResponseWriter, err error) {
	w.WriteHeader(500)
	w.Write([]byte(fmt.Sprintf("%s", err)))
}

func downloadTool(w http.ResponseWriter, r *http.Request) {
	exec_path, err := os.Executable()
	if err != nil {
		log.Error(err)
		writeDownloadError(w, err)
		return
	}
	download_path := exec_path
	desired_os := r.URL.Query().Get("os")
	if desired_os == "win" {
		download_path = fmt.Sprintf("%s-win", download_path)
	} else if desired_os == "mac" {
		download_path = fmt.Sprintf("%s-mac", download_path)
	}
	stat, err := os.Stat(download_path)
	if err != nil {
		log.Error(err)
		writeDownloadError(w, err)
		return
	}
	fl, err := os.OpenFile(download_path, os.O_RDONLY, 0644)
	if err != nil {
		log.Error(err)
		writeDownloadError(w, err)
		return
	}
	defer fl.Close()
	w.Header().Add("Content-Type", "application/octet-stream")
	w.Header().Add("Content-Length", fmt.Sprintf("%d", stat.Size()))
	w.Header().Add("Content-Disposition", "attachment; filename=\"ksamlauth\"")
	w.WriteHeader(200)
	written, err := io.Copy(w, fl)
	if err != nil {
		log.Error(err)
		writeDownloadError(w, err)
		return
	}
	if written != stat.Size() {
		err = fmt.Errorf("download: written size different: %d <> %d", written, stat.Size())
		log.Error(err)
		writeDownloadError(w, err)
		return
	}
}

func prepareStartWebServer(k8sconfig *KubernetesSAInfo, k8sendpoint, userconfig string) error {
	port := DEFAULT_LISTEN_PORT
	if os.Getenv(ENV_VAR_LISTEN_PORT) != "" {
		if val, err := strconv.Atoi(os.Getenv(ENV_VAR_LISTEN_PORT)); err == nil {
			if val > 0 && val < 65536 {
				port = val
			}
		} else {
			log.Errorf("The specified value in the environment variable %s is not a valid integer: %s\n", ENV_VAR_LISTEN_PORT, os.Getenv(ENV_VAR_LISTEN_PORT))
		}
	}
	if userconfig != "" {
		http.HandleFunc("/userconfig", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Add("Content-Type", "application/octet-stream")
			w.Header().Add("Content-Length", fmt.Sprintf("%d", len(userconfig)))
			w.Header().Add("Content-Disposition", "attachment; filename=\"ksamlauth.toml\"")
			w.WriteHeader(200)
			w.Write([]byte(userconfig))
		})
	}
	http.HandleFunc("/download", downloadTool)
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "running ...")
	})
	pm, _ := pem.Decode([]byte(os.Getenv(ENV_VAR_IDP_CERT)))
	cert, err := x509.ParseCertificate(pm.Bytes)
	if err != nil {
		return fmt.Errorf("parse cert error: %s", err)
	}
	vh := ValidateHandler{
		K8sConfig:   k8sconfig,
		Certificate: cert,
		K8sEndpoint: k8sendpoint,
	}
	http.Handle("/validate", &vh)
	log.Infof("Listening on port %d\n", port)
	return http.ListenAndServe(fmt.Sprintf(":%d", port), nil)
}

func checkServiceAccountFolder(fldr string, conf *KubernetesSAInfo) error {
	cacrt_path := path.Join(fldr, "ca.crt")
	token_path := path.Join(fldr, "token")
	cacrt_dt, err := ioutil.ReadFile(cacrt_path)
	if err != nil {
		return err
	}
	token_dt, err := ioutil.ReadFile(token_path)
	if err != nil {
		return err
	}
	(*conf).Cert = string(cacrt_dt)
	(*conf).Token = string(token_dt)
	return nil
}

var daemonCmd = &cobra.Command{
	Use:   "daemon",
	Short: "daemon runs inside a kubernetes cluster and performs validation and registration",
	Long: fmt.Sprintf(`This part of the program runs inside a kubernetes cluster as a deployment and
is exposed to the internet via an ingress. It accepts validation requests,
which if successful will create a new serviceaccount, or create a new
serviceaccount. The validation point will then return the secret token
of the serviceaccount as a JSON structure, so that it can be used by
kubectl for accessing the cluster.

This command needs a kubernetes serviceaccount with rights to create, modify
and delete serviceaccounts inside the namespace specified by the environment
variable %s. Usually the token is mounted at path
/var/run/secrets/kubernetes.io/serviceaccount, but this could be
overriden by specifying the environment variable %s.

By default the daemon runs on port %d, but this could be overriden with
the environment variable %s.

The certificate of the identity provider must be provided via the environment
variable %s.

Since writing your own ksamlauth.toml file as a client could be cumbersome,
cluster providers could set an example ksamlauth.toml file via the environment
variable %s. This can be downloaded then by calling the /userconfig endpoint.`,
		ENV_VAR_SA_NAMESPACE, ENV_VAR_NAME_TOKEN_DIR, DEFAULT_LISTEN_PORT, ENV_VAR_LISTEN_PORT, ENV_VAR_IDP_CERT, ENV_VAR_USERCONFIG),
	Run: func(cmd *cobra.Command, args []string) {
		if dodebug, err := cmd.Flags().GetBool("debug"); err != nil {
			log.Fatal(err)
			return
		} else if dodebug {
			log.SetLevel(log.DebugLevel)
		}
		path_to_admin_token := "/var/run/secrets/kubernetes.io/serviceaccount"
		if os.Getenv(ENV_VAR_NAME_TOKEN_DIR) != "" {
			path_to_admin_token = os.Getenv(ENV_VAR_NAME_TOKEN_DIR)
		}
		if os.Getenv(ENV_VAR_SA_NAMESPACE) == "" {
			log.Fatalf("the environment variable %s must be set", ENV_VAR_SA_NAMESPACE)
			return
		}
		if os.Getenv(ENV_VAR_IDP_CERT) == "" {
			log.Fatalf("the environment variable %s must be set", ENV_VAR_IDP_CERT)
			return
		}
		k8sendpoint := "https://kubernetes.default.svc:443"
		if os.Getenv(ENV_VAR_KUBERNETES_ENDPOINT) != "" {
			if _, err := url.Parse(os.Getenv(ENV_VAR_KUBERNETES_ENDPOINT)); err != nil {
				log.Errorf("The specified custom kubernetes endpoint via %s is invalid: %s", ENV_VAR_KUBERNETES_ENDPOINT, err)
			} else {
				k8sendpoint = os.Getenv(ENV_VAR_KUBERNETES_ENDPOINT)
			}
		}
		log.Debug("ServiceAccount token path: ", path_to_admin_token)
		var k8sconfig KubernetesSAInfo
		err := checkServiceAccountFolder(path_to_admin_token, &k8sconfig)
		if err != nil {
			log.Fatal(err)
			return
		}
		go saPruner(&k8sconfig, k8sendpoint)
		err = prepareStartWebServer(&k8sconfig, k8sendpoint, strings.TrimSpace(os.Getenv(ENV_VAR_USERCONFIG)))
		if err != nil {
			log.Fatal(err)
			return
		}
	},
}

func init() {

}
