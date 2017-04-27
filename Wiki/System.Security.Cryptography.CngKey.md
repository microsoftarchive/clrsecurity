# System.Security.Cryptography.CngKey

{""} 
{"The CngKeyExtensionMethods class provides several extension methods for the"} [System.Security.Cryptography.CngKey](http://msdn.microsoft.com/en-us/library/system.security.cryptography.cngkey.aspx) {". This type is in the Security.Cryptography namespace (not the System.Security.Cryptography namespace), so in order to use these extension methods, you will need to make sure you include this namespace as well as a reference to Security.Cryptography.dll."} 
 {""} 
{"CngKey uses the NCrypt layer of CNG, and requires Windows Vista and the .NET Framework 3.5."} 
 {""} 

## APIs

### [System.Security.Cryptography.X509Certificates.X509Certificate2](http://msdn.microsoft.com/en-us/library/system.security.cryptography.x509certificates.x509certificate2.aspx) CreateSelfSignedCertificate([System.Security.Cryptography.X509Certificates.X500DistinguishedName](http://msdn.microsoft.com/en-us/library/system.security.cryptography.x509certificates.x500distinguishedname.aspx) subjectName)

{"CreateSelfSignedCertificate creates a new self signed certificate issued to the specified subject. The certificate will contain the key used to create the self signed certificate. Since the certificate needs to be signed, the CngKey used must be usable for signing, which means it must also contain a private key. If there is no private key, the operation will fail with a CryptographicException indicating that "The key does not exist.""} 

{"This overload creates a certificate which does take ownership of the underlying key - which means that the input CngKey will be disposed before this method exits and should no longer be used by the caller."}

**Parameters:**
| subjectName | {"the name of hte subject the self-signed certificate will be issued to"}  |

**Exceptions:**
| [System.ArgumentNullException](http://msdn.microsoft.com/en-us/library/system.argumentnullexception.aspx) | {"if"} _subjectName_ {"is null"}  |
| [System.Security.Cryptography.CryptographicException](http://msdn.microsoft.com/en-us/library/system.security.cryptography.cryptographicexception.aspx) | {"if the certificate cannot be created"}  |


### [System.Security.Cryptography.X509Certificates.X509Certificate2](http://msdn.microsoft.com/en-us/library/system.security.cryptography.x509certificates.x509certificate2.aspx) CreateSelfSignedCertificate([Security.Cryptography.X509Certificates.X509CertificateCreationParameters](Security.Cryptography.X509Certificates.X509CertificateCreationParameters) creationParameters)

{"CreateSelfSignedCertificate creates a new self signed certificate issued to the specified subject. The certificate will contain the key used to create the self signed certificate. Since the certificate needs to be signed, the CngKey used must be usable for signing, which means it must also contain a private key. If there is no private key, the operation will fail with a CryptographicException indicating that "The key does not exist.""} 

{"If "} _creationParameters_ {" have TakeOwnershipOfKey set to true, the certificate generated will own the key and the input CngKey will be disposed to ensure that the caller doesn't accidentally use it beyond its lifetime (which is now controlled by the certificate object)."}

{"Conversely, if TakeOwnershipOfKey is set to false, the API requires full trust to use, and also requires that the caller ensure that the generated certificate does not outlive the input CngKey object."}

**Parameters:**
| creationParameters | {"parameters to customize the self-signed certificate"}  |

**Exceptions:**
| [System.ArgumentNullException](http://msdn.microsoft.com/en-us/library/system.argumentnullexception.aspx) | {"if"} _creationParameters_ {"is null"}  |
| [System.Security.Cryptography.CryptographicException](http://msdn.microsoft.com/en-us/library/system.security.cryptography.cryptographicexception.aspx) | {"if the certificate cannot be created"}  |


