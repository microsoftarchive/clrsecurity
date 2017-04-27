# System.Security.Cryptography.X509Certificates.X509Certificate

{"The X509CertificateExtensionMethods type provides extension methods for the"} [System.Security.Cryptography.X509Certificates.X509Certificate](http://msdn.microsoft.com/en-us/library/system.security.cryptography.x509certificates.x509certificate.aspx) {"class. X509CertificateExtensionMethods is in the Security.Cryptography.X509Certificates namespace (not the System.Security.Cryptography.X509Certificates namespace), so in order to use these extension methods, you will need to make sure you include this namespace as well as a reference to Security.Cryptography.dll."} 

## APIs

### System.Collections.Generic.IList<[Security.Cryptography.X509Certificates.X509AlternateName](Security.Cryptography.X509Certificates.X509AlternateName)> GetAlternateNames([Security.Cryptography.Oid2](Security.Cryptography.Oid2) alternateNameExtensionOid)

{"Get all the alternate names encoded under a specific extension OID. The"} [System.Security.Cryptography.X509Certificates.X509Certificate](System.Security.Cryptography.X509Certificates.X509Certificate)(System.Security.Cryptography.X509Certificates.X509Certificate).GetIssuerAlternateNames() {"and"} [System.Security.Cryptography.X509Certificates.X509Certificate](System.Security.Cryptography.X509Certificates.X509Certificate)(System.Security.Cryptography.X509Certificates.X509Certificate).GetSubjectAlternateNames() {"extension methods provide direct access to the subject and issuer names, which can be friendlier to use than this method."} 

**Parameters:**
| alternateNameExtensionOid | {"OID representing the alternate names to retrieve"}  |

**Exceptions:**
| [System.ArgumentNullException](http://msdn.microsoft.com/en-us/library/system.argumentnullexception.aspx) | {"if"} _alternateNameExtensionOid_ {"is null"}  |

**Permission Requirements:**
| [System.Security.PermissionSet](http://msdn.microsoft.com/en-us/library/system.security.permissionset.aspx) | {"The immediate caller must be fully trusted to use this method."}  |


### [Security.Cryptography.X509Certificates.SafeCertContextHandle](Security.Cryptography.X509Certificates.SafeCertContextHandle) GetCertificateContext()

{"Get a"} [Security.Cryptography.X509Certificates.SafeCertContextHandle](Security.Cryptography.X509Certificates.SafeCertContextHandle) {"for the X509 certificate. The caller of this method owns the returned safe handle, and should dispose of it when they no longer need it. This handle can be used independently of the lifetime of the original X509 certificate."} 

**Permission Requirements:**
| [System.Security.Permissions.SecurityPermission](http://msdn.microsoft.com/en-us/library/system.security.permissions.securitypermission.aspx) | {"The immediate caller must have SecurityPermission/UnmanagedCode to use this method"}  |


### System.Collections.Generic.IEnumerable<[Security.Cryptography.X509Certificates.X509AlternateName](Security.Cryptography.X509Certificates.X509AlternateName)> GetIssuerAlternateNames()

{"Get all of the alternate names a certificate has for its issuer"} 


### System.Collections.Generic.IEnumerable<[Security.Cryptography.X509Certificates.X509AlternateName](Security.Cryptography.X509Certificates.X509AlternateName)> GetSubjectAlternateNames()

{"Get all of the alternate names a certificate has for its subject"} 


### bool HasCngKey()

{"The HasCngKey method returns true if the X509Certificate is referencing a key stored with with NCrypt in CNG. It will return true if the certificate's key is a reference to a key stored in CNG, and false otherwise. For instance, if the key is stored with CAPI or if the key is not linked by the certificate and is contained directly in it, this method will return false."} 


