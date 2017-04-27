# Security.Cryptography.X509Certificates.X509CertificateCreationParameters

{"The X509CertificateCreationParameters class allows customization of the properties of an X509 certificate that is being created. For instance, these parameters can be used with the"} [System.Security.Cryptography.CngKey](System.Security.Cryptography.CngKey).CreateSelfSignedCertificate(Security.Cryptography.X509Certificates.X509CertificateCreationParameters) {"API."} 

## APIs

### .ctor([System.Security.Cryptography.X509Certificates.X500DistinguishedName](http://msdn.microsoft.com/en-us/library/system.security.cryptography.x509certificates.x500distinguishedname.aspx) subjectName)

{"Creates a new X509CertificateCreationParameters object which can be used to create a new X509 certificate issued to the specified subject."} 

**Parameters:**
| subjectName | {"The name of the subject the new certificate will be issued to"}  |

**Exceptions:**
| [System.ArgumentNullException](http://msdn.microsoft.com/en-us/library/system.argumentnullexception.aspx) | {"if"} _subjectName_ {"is null"}  |


### [Security.Cryptography.X509Certificates.X509CertificateCreationOptions](Security.Cryptography.X509Certificates.X509CertificateCreationOptions) CertificateCreationOptions { get; set; }

{"Gets or sets the flags used to create the X509 certificate. The default value is X509CertificateCreationOptions.DoNotLinkKeyInformation."} 

### [System.DateTime](http://msdn.microsoft.com/en-us/library/system.datetime.aspx) EndTime { get; set; }

{"Gets or sets the expiration date of the newly created certificate. If not set, this property defaults to one year after the X509CertificateCreationParameters object is constructed."} 

### [System.Security.Cryptography.X509Certificates.X509ExtensionCollection](http://msdn.microsoft.com/en-us/library/system.security.cryptography.x509certificates.x509extensioncollection.aspx) Extensions { get; }

{"The Extensions property holds a collection of the X509Extensions that will be applied to the newly created certificate."} 
**Permission Requirements:**
| [System.Security.Permissions.SecurityPermission](http://msdn.microsoft.com/en-us/library/system.security.permissions.securitypermission.aspx) | {"This property requires SecurityPermission/UnmanagedCode to access"}  |


### [Security.Cryptography.X509Certificates.X509CertificateSignatureAlgorithm](Security.Cryptography.X509Certificates.X509CertificateSignatureAlgorithm) SignatureAlgorithm { get; set; }

{"Gets or sets the algorithm which will be used to sign the newly created certificate. If this property is not set, the default value is X509CertificateSignatureAlgorithm.RsaSha1."} 
**Exceptions:**
| [System.ArgumentOutOfRangeException](http://msdn.microsoft.com/en-us/library/system.argumentoutofrangeexception.aspx) | {"if the value specified is not a member of the"} [Security.Cryptography.X509Certificates.X509CertificateSignatureAlgorithm](Security.Cryptography.X509Certificates.X509CertificateSignatureAlgorithm) {"enumeration."}  |



### [System.Security.Cryptography.X509Certificates.X500DistinguishedName](http://msdn.microsoft.com/en-us/library/system.security.cryptography.x509certificates.x500distinguishedname.aspx) SubjectName { get; set; }

{"Gets or sets the name of the subject that the newly created certificate will be issued to."} 
**Exceptions:**
| [System.ArgumentNullException](http://msdn.microsoft.com/en-us/library/system.argumentnullexception.aspx) | {"if SubjectName is set to a null value"}  |



### [System.DateTime](http://msdn.microsoft.com/en-us/library/system.datetime.aspx) StartTime { get; set; }

{"Gets or sets the time that the newly created certificate will become valid. If not set, this property defaults to the time that the X509CertificateCreationParameters object is created."} 

### bool TakeOwnershipOfKey { get; set; }

{"Gets or sets a value indicating which object owns the lifetime of the incoming key once the certificate is created.  If set to true, then the certificate owns the lifetime of the key and the key object may be destroyed.  If set to false, the key object continues to own the key lifetime and must therefore outlive the certificate."}