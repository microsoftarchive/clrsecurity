# Security.Cryptography.AuthenticatedAes

{"The AuthenticatedAes abstract base class forms the base class for concrete implementations of authenticated AES algorithms. For instance, AES with CCM or GCM chaining modes provides authentication, and therefore derive from AuthenticatedAes."} 

## APIs

### static [Security.Cryptography.AuthenticatedAes](Security.Cryptography.AuthenticatedAes) Create([System.String](http://msdn.microsoft.com/en-us/library/system.string.aspx) algorithm)

{"Create an instance of the specified AuthenticatedAes type. If the type cannot be found in"} [Security.Cryptography.CryptoConfig2](Security.Cryptography.CryptoConfig2) {", Create returns null."} 

**Parameters:**
| algorithm | {"name of the authenticated symmetric algorithm to create"}  |

**Exceptions:**
| [System.ArgumentNullException](http://msdn.microsoft.com/en-us/library/system.argumentnullexception.aspx) | {"if"} _algorithm_ {"is null"}  |


