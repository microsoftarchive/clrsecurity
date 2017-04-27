# Security.Cryptography.CngChainingMode

{"The CngChainingMode class provides a pseudo-enumeration similar to"} [System.Security.Cryptography.CngAlgorithm](http://msdn.microsoft.com/en-us/library/system.security.cryptography.cngalgorithm.aspx) {"which provides an enumeration over chaining modes that CNG supports. Several of the enumeration values are the CNG equivalents of the"} [System.Security.Cryptography.CipherMode](http://msdn.microsoft.com/en-us/library/system.security.cryptography.ciphermode.aspx) {"framework enumeration."} 

## APIs

### .ctor([System.String](http://msdn.microsoft.com/en-us/library/system.string.aspx) chainingMode)

{"Creates a new CngChainingMode for the chaining mode string. This constructor should generally not be used, and instead the built in values for the standard chaining modes should be preferred."} 

**Parameters:**
| chainingMode | {"chaining mode to create a CngChainingMode object for"}  |

**Exceptions:**
| [System.ArgumentException](http://msdn.microsoft.com/en-us/library/system.argumentexception.aspx) | {"if"} _chainingMode_ {"is empty"}  |
| [System.ArgumentNullException](http://msdn.microsoft.com/en-us/library/system.argumentnullexception.aspx) | {"if"} _chainingMode_ {"is null"}  |


### [System.String](http://msdn.microsoft.com/en-us/library/system.string.aspx) ChainingMode { get; }

{"Get the string which represents this chaining mode to CNG"} 

### static [Security.Cryptography.CngChainingMode](Security.Cryptography.CngChainingMode) Cbc { get; }

{"Gets a CngChainingMode object for the cipher block chaining mode. This is equivalent to CipherMode.Cbc in the managed enumeration."} 

### static [Security.Cryptography.CngChainingMode](Security.Cryptography.CngChainingMode) Ccm { get; }

{"Gets a CngChainingMode object for the counter with cipher block chaining MAC authenticated chaining mode."} 

### static [Security.Cryptography.CngChainingMode](Security.Cryptography.CngChainingMode) Cfb { get; }

{"Gets a CngChainingMode object for the cipher feedback mode. This is equivalent to CipherMode.Cfb in the managed enumeration."} 

### static [Security.Cryptography.CngChainingMode](Security.Cryptography.CngChainingMode) Ecb { get; }

{"Gets a CngChainingMode object for the electronic codebook mode. This is equivalent to CipherMode.Ecb in the managed enumeration."} 

### static [Security.Cryptography.CngChainingMode](Security.Cryptography.CngChainingMode) Gcm { get; }

{"Gets a CngChainingMode object for the counter with Galois/counter mode authenticated chaining mode."} 

