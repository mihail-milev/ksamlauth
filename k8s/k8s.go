package k8s

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
)

const (
	NOT_FOUND_ERROR = "not found"
)

// ffjson: skip
type Metadata struct {
	Name        string            `json:"name"`
	Namespace   string            `json:"namespace"`
	Annotations map[string]string `json:"annotations,omitempty"`
}

// ffjson: skip
type ServiceAccount struct {
	Metadata Metadata `json:"metadata"`
}

// ffjson: noencoder
type ServiceAccountList struct {
	Items []ServiceAccount `json:"items"`
}

// ffjson: skip
type SecretData struct {
	Token string `json:"token"`
}

// ffjson: skip
type Secret struct {
	Metadata Metadata   `json:"metadata"`
	Data     SecretData `json:"data"`
}

// ffjson: skip
type SecretList struct {
	Items []Secret `json:"items"`
}

type K8sConnection interface {
	GetAllSAinNamespace(namespace string) (*ServiceAccountList, error)
	SearchForSa(name, namespace string) (ServiceAccount, error)
	CreateSa(name, namespace string, annotations map[string]string) error
	GetTokenForSa(name, namespace string) (string, error)
	DeleteSa(name, namespace string) error
	PatchSaAnnotations(name, namespace string, annotations map[string]string) error
}

// ffjson: skip
type K8sConnectionDefault struct {
	HttpClient *http.Client
	Token      *string
	Address    string
}

func NewK8sConnection(token *string, cacert *x509.Certificate, address string) K8sConnection {
	certpool := x509.NewCertPool()
	certpool.AddCert(cacert)
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: certpool,
			},
		},
	}
	return &K8sConnectionDefault{
		HttpClient: client,
		Token:      token,
		Address:    address,
	}
}

func (k *K8sConnectionDefault) readAll(body io.Reader, size int) ([]byte, error) {
	buf := make([]byte, size)
	cnt := 0
	for {
		n, err := body.Read(buf[cnt:])
		if err != nil && err != io.EOF {
			return []byte{}, err
		}
		cnt += n
		if cnt >= size || err == io.EOF {
			return buf, nil
		}
	}
}

func (k *K8sConnectionDefault) performRestRequest(method, uri, body string, opts ...string) ([]byte, error) {
	req, err := http.NewRequest(method, k.Address+uri, nil)
	if err != nil {
		return []byte{}, err
	}
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Authorization", "Bearer "+*k.Token)
	if len(opts) > 0 {
		req.Header.Add("Content-Type", opts[0])
	} else {
		req.Header.Add("Content-Type", "application/json")
	}
	if body != "" {
		bodyReader := strings.NewReader(body)
		req.Body = io.NopCloser(bodyReader)
	}
	resp, err := k.HttpClient.Do(req)
	if err != nil {
		return []byte{}, err
	}
	var bodyDt []byte
	clString := resp.Header.Get("Content-Length")
	clInt, err := strconv.Atoi(clString)
	if clString == "" || err != nil {
		bodyDt, err = ioutil.ReadAll(resp.Body)
	} else {
		bodyDt, err = k.readAll(resp.Body, clInt)
	}
	resp.Body.Close()
	if err != nil {
		return []byte{}, err
	}
	if resp.StatusCode > 299 {
		return []byte{}, fmt.Errorf("HTTP status code: %d, Body: %s", resp.StatusCode, string(bodyDt))
	}
	return bodyDt, nil
}

func (k *K8sConnectionDefault) GetAllSAinNamespace(namespace string) (*ServiceAccountList, error) {
	var sal ServiceAccountList
	respBody, err := k.performRestRequest("GET", "/api/v1/namespaces/"+namespace+"/serviceaccounts", "")
	if err != nil {
		return &sal, err
	}
	/*err = json.Unmarshal(respBody, &sal)
	if err != nil {
		return &ServiceAccountList{}, err
	}*/
	err = sal.UnmarshalJSON(respBody)
	return &sal, err
}

func (k *K8sConnectionDefault) SearchForSa(name, namespace string) (ServiceAccount, error) {
	sas, err := k.GetAllSAinNamespace(namespace)
	if err != nil {
		return ServiceAccount{}, err
	}
	for _, sa := range sas.Items {
		if sa.Metadata.Name == name {
			return sa, nil
		}
	}
	return ServiceAccount{}, fmt.Errorf(NOT_FOUND_ERROR)
}

func (k *K8sConnectionDefault) CreateSa(name, namespace string, annotations map[string]string) error {
	newsa := ServiceAccount{
		Metadata: Metadata{
			Name:        name,
			Namespace:   namespace,
			Annotations: annotations,
		},
	}
	reqData, err := json.Marshal(&newsa)
	if err != nil {
		return err
	}
	_, err = k.performRestRequest("POST", fmt.Sprintf("/api/v1/namespaces/%s/serviceaccounts", namespace), string(reqData))
	return err
}

func (k *K8sConnectionDefault) GetTokenForSa(name, namespace string) (string, error) {
	respBody, err := k.performRestRequest("GET", fmt.Sprintf("/api/v1/namespaces/%s/secrets", namespace), "")
	if err != nil {
		return "", err
	}
	var sl SecretList
	err = json.Unmarshal(respBody, &sl)
	if err != nil {
		return "", err
	}
	for _, secret := range sl.Items {
		secret_annot_sa, secret_annot_sa_exists := secret.Metadata.Annotations["kubernetes.io/service-account.name"]
		if !secret_annot_sa_exists {
			continue
		}
		if secret_annot_sa == name {
			dt, err := base64.StdEncoding.DecodeString(secret.Data.Token)
			return string(dt), err
		}
	}
	return "", fmt.Errorf("token for SA %s not found", name)
}

func (k *K8sConnectionDefault) DeleteSa(name, namespace string) error {
	_, err := k.performRestRequest("DELETE", fmt.Sprintf("/api/v1/namespaces/%s/serviceaccounts/%s", namespace, name), "")
	return err
}

func (k *K8sConnectionDefault) PatchSaAnnotations(name, namespace string, annotations map[string]string) error {
	new_sa_dt := ServiceAccount{
		Metadata: Metadata{
			Name:        name,
			Namespace:   namespace,
			Annotations: annotations,
		},
	}
	bd, err := json.Marshal(&new_sa_dt)
	if err != nil {
		return err
	}
	_, err = k.performRestRequest("PATCH", fmt.Sprintf("/api/v1/namespaces/%s/serviceaccounts/%s", namespace, name), string(bd), "application/strategic-merge-patch+json")
	return err
}
