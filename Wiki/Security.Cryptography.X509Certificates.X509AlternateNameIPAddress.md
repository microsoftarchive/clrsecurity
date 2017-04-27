# Security.Cryptography.X509Certificates.X509AlternateNameIPAddress

{"X509 alternate name implementation for alternate names stored as IP addresses. The"} [Security.Cryptography.X509Certificates.AlternateNameType.IPAddress](Security.Cryptography.X509Certificates.AlternateNameType.IPAddress) {"alternate name type is stored as an IP address."} 

## APIs

### .ctor([Security.Cryptography.X509Certificates.AlternateNameType](Security.Cryptography.X509Certificates.AlternateNameType) type, [System.Net.IPAddress](http://msdn.microsoft.com/en-us/library/system.net.ipaddress.aspx) address)

{"Create an alternate name for the given IP address"} 

**Parameters:**
| type |  |
| address |  |

**Exceptions:**
| [System.ArgumentNullException](http://msdn.microsoft.com/en-us/library/system.argumentnullexception.aspx) | {"if"} _address_ {"is null"}  |


### [System.Net.IPAddress](http://msdn.microsoft.com/en-us/library/system.net.ipaddress.aspx) Address { get; }

{"IP address held in the name"} 

