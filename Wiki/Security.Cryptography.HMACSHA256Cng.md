# Security.Cryptography.HMACSHA256Cng

{""} 
{"The HMACSHA256Cng class provides a wrapper for the CNG implementation of the HMAC SHA256 algorithm. It provides the same interface as the other HMAC implementations shipped with the .NET Framework, including"} [System.Security.Cryptography.HMACSHA256](http://msdn.microsoft.com/en-us/library/system.security.cryptography.hmacsha256.aspx) {""} 
 {""} 
{"HMACSHA256Cng uses the BCrypt layer of CNG to do its work, and requires Windows Vista and the .NET Framework 3.5."} 
 {""} 
{"Since most of the HMACSHA256Cng APIs are inherited from the"} [System.Security.Cryptography.HMAC](http://msdn.microsoft.com/en-us/library/system.security.cryptography.hmac.aspx) {"base class, please see the MSDN documentation for HMAC for a complete description."} 
 {""} 

## APIs

### .ctor(System.Byte[]() key)

{"Constructs a HMACSHA256Cng object using the given key, which will use the Microsoft Primitive Algorithm Provider to do its work."} 

**Parameters:**
| key | {"key to use when calculating the HMAC"}  |

**Exceptions:**
| [System.ArgumentNullException](http://msdn.microsoft.com/en-us/library/system.argumentnullexception.aspx) | {"if"} _key_ {"is null"}  |


### .ctor(System.Byte[]() key, [System.Security.Cryptography.CngProvider](http://msdn.microsoft.com/en-us/library/system.security.cryptography.cngprovider.aspx) algorithmProvider)

{"Constructs a HMACSHA256Cng object using the given key, which will calculate the HMAC using the given algorithm provider and key."} 

**Parameters:**
| key | {"key to use when calculating the HMAC"}  |
| algorithmProvider | {"algorithm provider to calculate the HMAC in"}  |

**Exceptions:**
| [System.ArgumentNullException](http://msdn.microsoft.com/en-us/library/system.argumentnullexception.aspx) | {"if"} _key_ {"or"} _algorithmProvider_ {"are null"}  |


