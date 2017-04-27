# Security.Cryptography.X509Certificates.X509CertificateCreationOptions

{"The X509CertificateCreationOptions enumeration provides a set of flags for use when creating a new X509 certificate."} 

| None | {"Do not set any flags when creating the certificate"}  |
| DoNotSignCertificate | {"Create an unsigned certificate. This maps to the CERT_CREATE_SELFSIGN_NO_SIGN flag."}  |
| DoNotLinkKeyInformation | {"By default, certificates will reference their private keys by setting the CERT_KEY_PROV_INFO_PROP_ID; the DoNotLinkKeyInformation flag causes the certificate to instead contain the private key direclty rather than by reference. This maps to the CERT_CREATE_SELFSIGN_NO_KEY_INFO flag."}  |
