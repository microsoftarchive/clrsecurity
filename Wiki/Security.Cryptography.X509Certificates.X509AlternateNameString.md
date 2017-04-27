# Security.Cryptography.X509Certificates.X509AlternateNameString

{"X509 alternate name implementation for alternate names stored as strings. THe"} [Security.Cryptography.X509Certificates.AlternateNameType.DnsName](Security.Cryptography.X509Certificates.AlternateNameType.DnsName) {","} [Security.Cryptography.X509Certificates.AlternateNameType.EdiPartyName](Security.Cryptography.X509Certificates.AlternateNameType.EdiPartyName) {","} [Security.Cryptography.X509Certificates.AlternateNameType.RegisteredId](Security.Cryptography.X509Certificates.AlternateNameType.RegisteredId) {","} [Security.Cryptography.X509Certificates.AlternateNameType.Rfc822Name](Security.Cryptography.X509Certificates.AlternateNameType.Rfc822Name) {", and"} [Security.Cryptography.X509Certificates.AlternateNameType.Url](Security.Cryptography.X509Certificates.AlternateNameType.Url) {"alternate name types store their names as strings."} 

## APIs

### .ctor([Security.Cryptography.X509Certificates.AlternateNameType](Security.Cryptography.X509Certificates.AlternateNameType) type, [System.String](http://msdn.microsoft.com/en-us/library/system.string.aspx) name)

{"Create an alternate name for the given string"} 

**Parameters:**
| type |  |
| name |  |

**Exceptions:**
| [System.ArgumentNullException](http://msdn.microsoft.com/en-us/library/system.argumentnullexception.aspx) | {"if"} _name_ {"is null"}  |


### [System.String](http://msdn.microsoft.com/en-us/library/system.string.aspx) Name { get; }

{"Alternate name"} 

