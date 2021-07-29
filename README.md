# ksamlauth

ksamlauth is a small program, which enables authentication for Kubernetes clusters against a SAML2.0 capable identity provider. The exact principle of working is descibed in [my medium.com blog post](https://mihail-milev.medium.com/kubernetes-authentication-using-saml2-0-4167c0051ebe). Please, review the blog post for more information.

# Usage

Here is the image also available on the blog post:

![ksamlauth UML diagram](/assets/ksamlauth.png "ksamlauth UML diagram")

## Prerequisites

- buildah for building the container;
- podman, or skopeo, or docker for pushing the container to a registry;
- go 1.16.

## Procedure

**Important note:** the helm chart mentioned in step 3 below will configure "ksamlauth daemon" to store all users' service accounts into the same namespace where the daemon is deployed into. If you want to change this behaviour, you have to heavily modify the helm charts - changing the corresponding environment variable, roles and role bindings.

1. Compile the program by executing (optional if you don't want to download my pre-compiled image - see step 2)
```
make
```
2. push the image to a registry, which your cluster can pull images from, or download it from [my ghcr.io repo](https://github.com/mihail-milev/ksamlauth/pkgs/container/ksamlauth);
3. use the [helm charts](/chart) to deploy the daemon. The two parameters "ingressURL" and "idpCertificate" MUST be set. The parameter "userconfigFile" is optional. Use the parameter "image" if you want to use your custom built image
```
helm install --set ingressURL=ksamlauth.url-to-cluster.com --set idpCertificate="$(cat idpcert.crt)" --set userconfigFile="$(cat provided_ksamlauth.toml)" -n users ksamlauth ./chart
```
4. wait for the pod to become ready and download the client by executing the following command. This will download the Linux binary, but if you specify "?os=mac" or "?os=win" at the end, the binary for the corresponding OS will be downloaded.
```
curl -o ksamlauth https://url-to-ksamlauth-ingress.com/download
```
5. generate a configuration file using 
```
./ksamlauth login --generate-default-config
```
6. modify the file ~/.kube/ksamlauth.toml by adding your private key and certificate, also the IdP endpoint and the client-/entity-id. Optionally add some clusters to the configuration file, in order to get a kubeconfig file automatically generated. If an example config file was provided during the deployment by setting "userconfigFile" (see step 3), then it can be obtained by calling
```
curl -o ~/.kube/ksamlauth.toml https://url-to-ksamlauth-ingress.com/userconfig
```
7. execute the following command and copy the URL printed in the console. Paste the URL in your browser
```
./ksamlauth login
```
8. authenticate against your IdP and wait for the terminal application "./ksamlauth login" to terminate automatically;
9. set the environment variable KUBECONFIG by calling (for bash-compatible shells)
```
export KUBECONFIG=~/.kube/ksamlauth.kubeconfig
```
10. use "kubectl" as usual. For example: 
```
kubectl get ns
```

# User configuration file

Under the configuration folder (by default ~/.kube) "ksamlauth login" will search for a configuration file (by default named "ksamlauth.toml") in TOML syntax. A generic file can be generated using the command in step 5 above. The structure of the file is as follows:

```toml
[global]
port = 16160
endpoint = "https://url.to.idp/endpoint"
entity_id = "entitiy-or-client-id-as-per-IdP"
my_key = "-----BEGIN RSA PRIVATE KEY-----\nmy own private key data comes in here\n-----END RSA PRIVATE KEY-----"
my_certificate = "-----BEGIN CERTIFICATE-----\nmy own certificate data comes in here\n-----END CERTIFICATE-----"

# [[clusters]]
# ca_cert_base64 = "base64-encoded-CA-from-cluster"
# master_endpoint = "https://master.some-cluster.com:6443"
# name = "some-cluster-name"
# ksamlauth_endpoint = "https://ksamlauth.some-cluster.com"
# ksamlauth_cmdline_opts = [""]

# [[clusters]]
# ca_cert_base64 = "base64-encoded-CA-from-another-cluster"
# master_endpoint = "https://master.some-other-cluster.com:6443"
# name = "some-other-cluster-name"
# ksamlauth_endpoint = "https://ksamlauth.some-other-cluster.com"
# ksamlauth_cmdline_opts = [""]

```

- "[global]" is the section which defines configuration settings for the identity provider of your choice;
- "port" defines on which port "ksamlauth login" will start a small HTTP server. This HTTP server will receive the SAML2.0 Response from the identity provider. By default this is 16160, so "ksamlauth login" will listen on "http://localhost:16160" for the response;
- "endpoint" defines the URL at which your identity provider listens for SAML2.0 AuthnRequests. This is something you could obtain either from the IdP's configuration console, or from its metadata.xml. Search for a tag with the name "SingleSignOnService". If there are many of them, take the one with the attribute 'Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"';
- "entity_id" is the unique identifier of your authentication at the IdP. Some IdPs call this also "client-id". It is a string, which the IdP uses to identify your configuration among many other SAML2.0 configurations;
- "my_key" and "my_certificate" is a private key and certificate pair, which either are generated by your IdP for you, or you've generated them with the openssl command yourself. If you've generated them yourself, don't forget to upload the certificate to your IdP. The private key is being used by "ksamlauth login" to generate the signature of the AuthnRequest towards the IdP. Both - the AuthnRequest and the signature - are sent to the IdP and the IdP then uses the certificate to verify the signature;
- "[[clusters]]" can exist inside the configuration file 0 to many times. It is an array (note the double square brackets). These are Kubernetes cluster configurations. If at least one such configuration is defined, then "ksamlauth login" will generate a kubeconfig file automatically (by default at ~/.kube/ksamlauth.kubeconfig");
- "ca_cert_base64" is the base64 encoded CA certificate of the cluster itself. You can get this one from the cluster-admin (or kubeadmin) kubeconfig of your cluster;
- "master_endpoint" is the URL (with FQDN and port if needed) at which the master API of your Kubernetes cluster is listening for requests. You can obtain this one from the cluster-admin (or kubeadmin) kubeconfig of your cluster;
- "name" is a name of the cluster, which will be used to identify it uniquely amon the other clusters in the newly generated kubeconfig file;
- "ksamlauth_endpoint" is the ingress URL of the "ksamlauth daemon" in your cluster. This was defined during the "ksamlauth daemon" deployment in step 3 above;
- "ksamlauth_cmdline_opts" is an array of strings, which will be then passed to "ksamlauth validate" when kubectl is being executed. This is useful for example to pass "--insecure-skip-tls-verify" if your ksamlauth ingress endpoint uses a self-signed certificate.

# Some notes

**About VMs:** as described above, "ksamlauth login" spawns a small HTTP server during login. This server, thus the "ksamlauth login" program must run on the same system, where also the browser is being opened and the login process is accomplished, because the browser will try to reach localhost. If you run "ksamlauth login" in a VM, then the browser must also open inside the VM, not on the host, or a remote machine.

# TODO

A lot ...

1. Let "ksamlauth login" first verify the SAML response before it is saved to a file;
2. test some edge cases for "ksamlauth daemon";
3. extend the Helm charts with more options.

# License

This source code is licensed under the MIT license. Please, view [LICENSE.md](/LICENSE.md) for more information.