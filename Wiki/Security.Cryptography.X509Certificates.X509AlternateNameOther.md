# Security.Cryptography.X509Certificates.X509AlternateNameOther

{"X509 alternate name implementation for other forms of alternate names. This type always uses the"} [Security.Cryptography.X509Certificates.AlternateNameType.OtherName](Security.Cryptography.X509Certificates.AlternateNameType.OtherName) {"alternate name type, and should have its type determined via the value in its"} [Security.Cryptography.X509Certificates.X509AlternateNameOther.Oid](Security.Cryptography.X509Certificates.X509AlternateNameOther.Oid) {"property."} 

## APIs

### .ctor([System.Byte[](System.Byte[)()()|http://msdn.microsoft.com/en-us/library/system.byte[]()().aspx] blob, [Security.Cryptography.Oid2](Security.Cryptography.Oid2) oid)

{"Create an alternate name for the given blob"} 

**Parameters:**
| blob | {"raw alternate name blob"}  |
| oid | {"OID describing the type of alternate name"}  |

**Exceptions:**
| [System.ArgumentNullException](http://msdn.microsoft.com/en-us/library/system.argumentnullexception.aspx) | {"if"} _blob_ {"or"} _oid_ {"are null"}  |


### [Security.Cryptography.Oid2](Security.Cryptography.Oid2) Oid { get; }

{"Get the OID representing the type of this alternate name"} 

