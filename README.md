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

# TODO

A lot ...

1. Let "ksamlauth login" first verify the SAML response before it is saved to a file;
2. test some edge cases for "ksamlauth daemon";
3. extend the Helm charts with more options.

# License

This source code is licensed under the MIT license. Please, view [LICENSE.md](/LICENSE.md) for more information.