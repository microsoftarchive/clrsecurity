# System.Security.Cryptography.X509Certificates.X509Certificate2

{"The X509Certificate2ExtensionMethods type provides several extension methods for the"} [System.Security.Cryptography.X509Certificates.X509Certificate2](http://msdn.microsoft.com/en-us/library/system.security.cryptography.x509certificates.x509certificate2.aspx) {"class. This type is in the Security.Cryptography.X509Certificates namespace (not the System.Security.Cryptography.X509Certificates namespace), so in order to use these extension methods, you will need to make sure you include this namespace as well as a reference to Security.Cryptography.dll."} 

## APIs

### [System.Security.Cryptography.CngKey](http://msdn.microsoft.com/en-us/library/system.security.cryptography.cngkey.aspx) GetCngPrivateKey()

{""} 
{"The GetCngPrivateKey method will return a"} [System.Security.Cryptography.CngKey](http://msdn.microsoft.com/en-us/library/system.security.cryptography.cngkey.aspx) {"representing the private key of an X.509 certificate which has its private key stored with NCrypt rather than with CAPI. If the key is not stored with NCrypt or if there is no private key available, GetCngPrivateKey returns null."} 
 {""} 
{"The HasCngKey method can be used to test if the certificate does have its private key stored with NCrypt."} 
 {""} 
{"The X509Certificate that is used to get the key must be kept alive for the lifetime of the CngKey that is returned - otherwise the handle may be cleaned up when the certificate is finalized."}

