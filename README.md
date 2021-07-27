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

1. Compile the program by executing
```
make
```
2. push the image to a registry, which your cluster can pull images from;
3. download the example [install.yaml](/assets/install.yaml) file. There are 4 fields in the form "{{.Template.XXX}}", which need to be defined by you. After these have been defined, execute
```
kubectl apply -n {desired-namespace} -f install.yaml
```
4. wait for the pod to become ready and download the client by executing
```
curl -o ksamlauth https://url-to-ksamlauth-ingress.com/download
```
5. generate a configuration file using 
```
./ksamlauth login --generate-default-config
```
6. modify the file ~/.kube/ksamlauth.toml by adding your private key and certificate, also the IdP endpoint and the client-/entity-id. Optionally add some clusters to the configuration file, in order to get a kubeconfig file automatically generated;
7. call
```
./ksamlauth login
```
copy the URL and paste it in your browser;
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
3. Helm chart?

# License

This source code is licensed under the MIT license. Please, view [LICENSE.md](/LICENSE.md) for more information.