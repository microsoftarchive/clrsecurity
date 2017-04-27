# Security.Cryptography.AuthenticatedSymmetricAlgorithm

{""} 
{"The AuthenticatedSymmetricAlgorithm abstract base class forms the base class for symmetric algorithms which support authentication as well as encryption. Authenticated symmetric algorithms produce an authentication tag in addition to ciphertext, which allows data to be both authenticated and protected for privacy. For instance, AES with CCM or GCM chaining modes provides authentication, and therefore derive from AuthenticatedSymmetricAlgorithm."} 
 {""} 
{"AuthenticatedSymmetricAlgorithm derives from"} [System.Security.Cryptography.SymmetricAlgorithm](http://msdn.microsoft.com/en-us/library/system.security.cryptography.symmetricalgorithm.aspx) {", so all of the SymmetricAlgorithm APIs also apply to AuthenticatedSymmericAlgorithm objects."} 
 {""} 

## Fields

| LegalTagSizesValue | {"The LegalTagSizes field is set by authenticated symmetric algorithm implementations to be the set of valid authentication tag sizes expressed in bits."}  |
| TagSizeValue | {"The TagSizeValue field contains the current authentication tag size used by the authenticated symmetric algorithm, expressed in bits."}  |
## APIs

### [System.Byte[](System.Byte[)()()|http://msdn.microsoft.com/en-us/library/system.byte[]()().aspx] AuthenticatedData { get; set; }

{""} 
{"Gets or sets the authenticated data buffer."} 
 {""} 
{"This data is included in calculations of the authentication tag, but is not included in the ciphertext. A value of null means that there is no additional authenticated data."} 
 {""} 

### [System.Byte[](System.Byte[)()()|http://msdn.microsoft.com/en-us/library/system.byte[]()().aspx] IV { get; set; }

{"Get or set the IV (nonce) to use with transorms created with this object."} 
**Exceptions:**
| [System.ArgumentNullException](http://msdn.microsoft.com/en-us/library/system.argumentnullexception.aspx) | {"if set to null"}  |



### [System.Security.Cryptography.KeySizes[](System.Security.Cryptography.KeySizes[)()()|http://msdn.microsoft.com/en-us/library/system.security.cryptography.keysizes[]()().aspx] LegalTagSizes { get; }

{"Gets the ranges of legal sizes for authentication tags produced by this algorithm, expressed in bits."} 

### [System.Byte[](System.Byte[)()()|http://msdn.microsoft.com/en-us/library/system.byte[]()().aspx] Tag { get; set; }

{"Gets or sets the authentication tag to use when verifying a decryption operation. This value is only read for decryption operaions, and is not used for encryption operations. To find the value of the tag generated on encryption, check the Tag property of the IAuthenticatedCryptoTransform encryptor object."} 
**Exceptions:**
| [System.ArgumentNullException](http://msdn.microsoft.com/en-us/library/system.argumentnullexception.aspx) | {"if the tag is set to null"}  |

| [System.ArgumentException](http://msdn.microsoft.com/en-us/library/system.argumentexception.aspx) | {"if the tag is not a legal size"}  |



### int TagSize { get; set; }

{"Get or set the size (in bits) of the authentication tag"} 
**Exceptions:**
| [System.ArgumentException](http://msdn.microsoft.com/en-us/library/system.argumentexception.aspx) | {"if the value is not a legal tag size"}  |



### static [Security.Cryptography.AuthenticatedSymmetricAlgorithm](Security.Cryptography.AuthenticatedSymmetricAlgorithm) Create([System.String](http://msdn.microsoft.com/en-us/library/system.string.aspx) algorithm)

{"Create an instance of the specified AuthenticatedSymmetricAlgorithm type. If the type cannot be found in"} [Security.Cryptography.CryptoConfig2](Security.Cryptography.CryptoConfig2) {", Create returns null."} 

**Parameters:**
| algorithm | {"name of the authenticated symmetric algorithm to create"}  |

**Exceptions:**
| [System.ArgumentNullException](http://msdn.microsoft.com/en-us/library/system.argumentnullexception.aspx) | {"if"} _algorithm_ {"is null"}  |


### [Security.Cryptography.IAuthenticatedCryptoTransform](Security.Cryptography.IAuthenticatedCryptoTransform) CreateAuthenticatedEncryptor([System.Byte[](System.Byte[)()()()()|http://msdn.microsoft.com/en-us/library/system.byte[]()()()().aspx] rgbKey, [System.Byte[](System.Byte[)()()()()|http://msdn.microsoft.com/en-us/library/system.byte[]()()()().aspx] rgbIV)

{"Create an authenticated encryptor using the specified key and nonce, and using the authenticated data from the property of this algorithm object."} 

**Parameters:**
| rgbKey | {"key to use for the encryption operation"}  |
| rgbIV | {"nonce to use for the encryption operation"}  |


### [Security.Cryptography.IAuthenticatedCryptoTransform](Security.Cryptography.IAuthenticatedCryptoTransform) CreateAuthenticatedEncryptor([System.Byte[](System.Byte[)()()()()()()|http://msdn.microsoft.com/en-us/library/system.byte[]()()()()()().aspx] rgbKey, [System.Byte[](System.Byte[)()()()()()()|http://msdn.microsoft.com/en-us/library/system.byte[]()()()()()().aspx] rgbIV, [System.Byte[](System.Byte[)()()()()()()|http://msdn.microsoft.com/en-us/library/system.byte[]()()()()()().aspx] rgbAuthenticatedData)

{"Create an authenticated encryptor using the specified key, nonce, and authenticated data."} 

**Parameters:**
| rgbKey | {"key to use for the encryption operation"}  |
| rgbIV | {"nonce to use for the encryption operation"}  |
| rgbAuthenticatedData | {"optional extra authenticated data to use for the encryption operation"}  |


### [System.Security.Cryptography.ICryptoTransform](http://msdn.microsoft.com/en-us/library/system.security.cryptography.icryptotransform.aspx) CreateDecryptor([System.Byte[](System.Byte[)()()()()|http://msdn.microsoft.com/en-us/library/system.byte[]()()()().aspx] rgbKey, [System.Byte[](System.Byte[)()()()()|http://msdn.microsoft.com/en-us/library/system.byte[]()()()().aspx] rgbIV)

{"Create a decryptor with the given key and nonce, using the authenticated data and authentication tag from the properties of the algorithm object."} 

**Parameters:**
| rgbKey | {"key to use for the decryption operation"}  |
| rgbIV | {"nonce to use for the decryption operation"}  |


### [System.Security.Cryptography.ICryptoTransform](http://msdn.microsoft.com/en-us/library/system.security.cryptography.icryptotransform.aspx) CreateDecryptor([System.Byte[](System.Byte[)()()()()()()()()|http://msdn.microsoft.com/en-us/library/system.byte[]()()()()()()()().aspx] rgbKey, [System.Byte[](System.Byte[)()()()()()()()()|http://msdn.microsoft.com/en-us/library/system.byte[]()()()()()()()().aspx] rgbIV, [System.Byte[](System.Byte[)()()()()()()()()|http://msdn.microsoft.com/en-us/library/system.byte[]()()()()()()()().aspx] rgbAuthenticatedData, [System.Byte[](System.Byte[)()()()()()()()()|http://msdn.microsoft.com/en-us/library/system.byte[]()()()()()()()().aspx] rgbTag)

{"Create a decryption transform with the given key, nonce, authenticated data, and authentication tag."} 

**Parameters:**
| rgbKey | {"key to use for the decryption operation"}  |
| rgbIV | {"nonce to use for the decryption operation"}  |
| rgbAuthenticatedData | {"optional extra authenticated data to use for the decryption operation"}  |
| rgbTag | {"authenticated tag to verify while decrypting"}  |


### [System.Security.Cryptography.ICryptoTransform](http://msdn.microsoft.com/en-us/library/system.security.cryptography.icryptotransform.aspx) CreateEncryptor([System.Byte[](System.Byte[)()()()()|http://msdn.microsoft.com/en-us/library/system.byte[]()()()().aspx] rgbKey, [System.Byte[](System.Byte[)()()()()|http://msdn.microsoft.com/en-us/library/system.byte[]()()()().aspx] rgbIV)

{"Create an encryptor using the given key and nonce, and the authenticated data from this algorithm."} 

**Parameters:**
| rgbKey |  |
| rgbIV |  |


### bool ValidTagSize(int tagSize)

{"Determine if an authentication tag size (in bits) is valid for use with this algorithm."} 

**Parameters:**
| tagSize | {"authentication tag size in bits to check"}  |


