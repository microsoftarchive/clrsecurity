# Security.Cryptography.X509Certificates.SafeCertContextHandle

{""} 
{"SafeCertContextHandle provides a SafeHandle class for an X509Certificate's certificate context as stored in its"} [System.Security.Cryptography.X509Certificates.X509Certificate.Handle](http://msdn.microsoft.com/en-us/library/system.security.cryptography.x509certificates.x509certificate.handle.aspx) {"property. This can be used instead of the raw IntPtr to avoid races with the garbage collector, ensuring that the X509Certificate object is not cleaned up from underneath you while you are still using the handle pointer."} 
 {""} 
This safe handle type represents a native CERT_CONTEXT. ([http://msdn.microsoft.com/en-us/library/aa377189.aspx)](http://msdn.microsoft.com/en-us/library/aa377189.aspx)) 
 {""} 
{"A SafeCertificateContextHandle for an X509Certificate can be obtained by calling the"} [System.Security.Cryptography.X509Certificates.X509Certificate](System.Security.Cryptography.X509Certificates.X509Certificate).GetCertificateContext() {"extension method."} 
 {""} 

**Permission Requirements:**
| [System.Security.Permissions.SecurityPermission](http://msdn.microsoft.com/en-us/library/system.security.permissions.securitypermission.aspx) | {"The immediate caller must have SecurityPermission/UnmanagedCode to use this type."}  |

