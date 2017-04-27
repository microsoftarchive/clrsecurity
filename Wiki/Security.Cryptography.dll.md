# Security.Cryptography.dll

Security.Cryptography.dll provides a new set of algorithm implementations to augment the built in .NET framework supported algorithms.  It also provides some APIs to extend the existing framework cryptography APIs.  All of the CNG APIs provided in this library require Windows Vista or greater to run.  AuthenticatedAesCng additionally requires Windows Vista SP1 or greater.  The library itself is built upon the .NET Framework version 3.5.  The sources are provided in a Visual Studio 2013 project.

## Download
[release:138352](release_138352)

## Class Reference

**[Security.Cryptography.AesCng](Security.Cryptography.AesCng)** - A managed wrapper around the CNG implementation of the AES algorithm.
**[Security.Cryptography.AuthenticatedAes](Security.Cryptography.AuthenticatedAes)** - Base class for implementations of the authenticated AES algorithm.
**[Security.Cryptography.AuthenticatedAesCng](Security.Cryptography.AuthenticatedAesCng)** - A managed wrapper around the CNG implementation of the authenticated AES algorithm.
**[Security.Cryptography.AuthenticatedSymmetricAlgorithm](Security.Cryptography.AuthenticatedSymmetricAlgorithm)** - Base class for authenticated symmetric algorithms to derive from.
**[Security.Cryptography.CngAlgorithm2](Security.Cryptography.CngAlgorithm2)** - A set of additional [CngAlgorithm](http://msdn.microsoft.com/en-us/library/system.security.cryptography.cngalgorithm.aspx) objects for algorithms not in the framework's CngAlgorithm type.
**[Security.Cryptography.CngChainingMode](Security.Cryptography.CngChainingMode)** - Pseudo-enumeration of chaining modes supported by CNG.
**[Security.Cryptography.CngProvider2](Security.Cryptography.CngProvider2)** - A set of additional [CngProvider](http://msdn.microsoft.com/en-us/library/system.security.cryptography.cngprovider.aspx) objects for providers not in the framework's CngProvider type.
**[Security.Cryptography.CngProviderCollection](Security.Cryptography.CngProviderCollection)** - Enumerates over the installed CNG providers on the machine
**[Security.Cryptography.CryptoConfig2](Security.Cryptography.CryptoConfig2)** - Provides [CryptoConfig](http://msdn.microsoft.com/en-us/library/system.security.cryptography.cryptoconfig.aspx) like access to all of the algorithms included in standard CryptoConfig, as well as the algorithms in the .NET 3.5 System.Core.dll assembly and in the Security.Cryptography.dll assembly.
**[Security.Cryptography.HMACSHA256Cng](Security.Cryptography.HMACSHA256Cng)** - A managed wrapper around the CNG implementation of HMAC SHA256.
**[Security.Cryptography.HMACSHA384Cng](Security.Cryptography.HMACSHA384Cng)** - A managed wrapper around the CNG implementation of HMAC SHA384.
**[Security.Cryptography.HMACSHA512Cng](Security.Cryptography.HMACSHA512Cng)** - A managed wrapper around the CNG implementation of HMAC SHA512.
**[Security.Cryptography.IAuthenticatedCryptoTransform](Security.Cryptography.IAuthenticatedCryptoTransform)** - Interface for crypto transforms that support generating an authentication tag.
**[Security.Cryptography.ICngAlgorithm](Security.Cryptography.ICngAlgorithm)** - Interface for algorithms which wrap CNG to provide information about the CNG algorithm they're wrapping.
**[Security.Cryptography.ICngAsymmetricAlgorithm](Security.Cryptography.ICngAsymmetricAlgorithm)** - Interface for asymmetric algorithms which wrap CNG to provide information about the CNG algorithm they're wrapping.
**[Security.Cryptography.ICngSymmetricAlgorithm](Security.Cryptography.ICngSymmetricAlgorithm)** - Interface for symmetric algorithms which wrap CNG to provide information about the CNG algorithm they're wrapping.
**[Security.Cryptography.ICryptoTransform2](Security.Cryptography.ICryptoTransform2)** - Extended crypto transform interface which provides additional information about the transform's capabilities.
**[Security.Cryptography.Oid2](Security.Cryptography.Oid2)** - An enhanced OID class.
**[Security.Cryptography.OidGroup](Security.Cryptography.OidGroup)** - Enumeration of recognized OID categories
**[Security.Cryptography.OidRegistrationOptions](Security.Cryptography.OidRegistrationOptions)** - Flags for use when registering a new OID on the machine
**[Security.Cryptography.BCryptPBKDF2](https://clrsecurity.codeplex.com/SourceControl/latest#Security.Cryptography/src/BCryptPBKDF2.cs)** - A managed wrapper around the CNG password-based key derivation function PBKDF2
**[Security.Cryptography.RNGCng](Security.Cryptography.RNGCng)** - A managed wrapper around the CNG random number generator
**[Security.Cryptography.RSACng](Security.Cryptography.RSACng)** - A managed wrapper around the CNG implementation of the RSA algorithm
**[Security.Cryptography.RSAPKCS1SHA256SignatureDescription](Security.Cryptography.RSAPKCS1SHA256SignatureDescription)** - A signature description class for RSA-SHA256 signatures.
**[Security.Cryptography.TripleDESCng](Security.Cryptography.TripleDESCng)** - A managed wrapper around the CNG implementation of the 3DES algorithm

**[Security.Cryptography.X509Certificates.AlternateNameType](Security.Cryptography.X509Certificates.AlternateNameType)** - Types of alternate names exposed by X509 certificates
**[Security.Cryptography.X509Certificates.SafeCertContextHandle](Security.Cryptography.X509Certificates.SafeCertContextHandle)** - Safe handle class which exposes an X509 certificate's CERT_CONTEXT
**[Security.Cryptography.X509Certificates.X509AlternateName](Security.Cryptography.X509Certificates.X509AlternateName)** - Base type for alternate name data exposed on an X509 certificate
**[Security.Cryptography.X509Certificates.X509AlternateNameBlob](Security.Cryptography.X509Certificates.X509AlternateNameBlob)** - Exposes alternate name data stored as a blob
**[Security.Cryptography.X509Certificates.X509AlternateNameIPAddress](Security.Cryptography.X509Certificates.X509AlternateNameIPAddress)** - Exposes alterante name data stored as an IP address
**[Security.Cryptography.X509Certificates.X509AlternateNameOther](Security.Cryptography.X509Certificates.X509AlternateNameOther)** - Exposes other alternate name data, along with an identification OID
**[Security.Cryptography.X509Certificates.X509AlternateNameString](Security.Cryptography.X509Certificates.X509AlternateNameString)** - Exposes alternate name data stored as a string
**[Security.Cryptography.X509Certificates.X509CertificateCreationOptions](Security.Cryptography.X509Certificates.X509CertificateCreationOptions)** - Flags for use when creating a new X509 certificate
**[Security.Cryptography.X509Certificates.X509CertificateCreationParameters](Security.Cryptography.X509Certificates.X509CertificateCreationParameters)** - Configuration parameters for use when creating a new X509 certificate
**[Security.Cryptography.X509Certificates.X509CertificateSignatureAlgorithm](Security.Cryptography.X509Certificates.X509CertificateSignatureAlgorithm)** - Algorithms which can be used to sign a new X509 certificate

**[Security.Cryptography.Xml.TransformFactory](Security.Cryptography.Xml.TransformFactory)** - A factory to aid in programmatically creating XML digital signature transforms.
**[Security.Cryptography.Xml.XmlDsigXPathWithNamespacesTransform](Security.Cryptography.Xml.XmlDsigXPathWithNamespacesTransform)** - An alternate implementation of the XmlDsigXPathTransform which allows the XPath expression to use all XML namespaces in scope for the XPath node in the transform.

**[System.Security.Cryptography.CngProvider](System.Security.Cryptography.CngProvider)** - A set of extension methods for the CngProvider type
**[System.Security.Cryptography.CngKey](System.Security.Cryptography.CngKey)** - A set of extension methods for the CngKey type

**[System.Security.Cryptography.X509Certificates.X509Certificate](System.Security.Cryptography.X509Certificates.X509Certificate)** - A set of extension methods for the X509Certificate type
**[System.Security.Cryptography.X509Certificates.X509Certificate2](System.Security.Cryptography.X509Certificates.X509Certificate2)** - A set of extension methods for the X509Certificate2 type

**[System.Security.Cryptography.Xml.EncryptedXml](System.Security.Cryptography.Xml.EncryptedXml)** - A set of extension methods for the EncryptedXml type