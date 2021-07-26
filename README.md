# ksamlauth

ksamlauth is a small program, which enables authentication for Kubernetes clusters against a SAML2.0 capable identity provider. The exact principle of working is descibed in [my medium.com blog post](https://mihail-milev.medium.com/kubernetes-authentication-using-saml2-0-4167c0051ebe). Please, review the blog post for more information.

# Usage

Here is the image also available on the blog post:

![ksamlauth UML diagram](/assets/ksamlauth.png "ksamlauth UML diagram")

1. Compile the program;
2. create a container containing the executable;
3. deploy the container and set the environment variables as described inside the "ksamlauth daemon" help;
4. expose the daemon using an ingress;
5. configure your IdP as described in the blog post;
6. authenticate using "ksamlauth login";
7. use the example kubeconfig file for your own kubeconfig and then perform kubectl actions as usual.

# TODO

A lot ...

1. Let "ksamlauth login" first verify the SAML response before it is saved to a file;
2. generate kubeconfig automatically;
3. replace the cURL part inside the kubeconfig with something like "ksamlauth validate";
4. create buildah script and a Makefile for automatic container creation;
5. test some edge cases for "ksamlauth daemon".

# License

This source code is licensed under the MIT license. Please, view [LICENSE.md](/LICENSE.md) for more information.