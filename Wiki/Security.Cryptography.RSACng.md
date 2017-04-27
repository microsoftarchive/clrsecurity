# Security.Cryptography.RSACng

{""} 
{"The RSACng class provides a wrapper for the CNG implementation of the RSA algorithm. The interface provided by RSACng is derived from the"} [System.Security.Cryptography.RSA](http://msdn.microsoft.com/en-us/library/system.security.cryptography.rsa.aspx) {"base type, and not from the"} [System.Security.Cryptography.RSACryptoServiceProvider](http://msdn.microsoft.com/en-us/library/system.security.cryptography.rsacryptoserviceprovider.aspx) {"class. Consequently, it is not a drop in replacement for existing uses of RSACryptoServiceProvider."} 
 {""} 
{"RSACng uses a programming model more similar to the"} [System.Security.Cryptography.ECDsaCng](http://msdn.microsoft.com/en-us/library/system.security.cryptography.ecdsacng.aspx) {"class than RSACryptoServiceProvider. For instance, unlike RSACryptoServiceProvider which has a key directly tied into the operations of the type itself, the key used by RsaCng is managed by a separate"} [System.Security.Cryptography.CngKey](http://msdn.microsoft.com/en-us/library/system.security.cryptography.cngkey.aspx) {"object. Additionally, operations such as signing and verifying signatures take their parameters from a set of properties set on the RSACng object, similar to how ECDsaCng uses properties of its object to control the signing and verification operations."} 
 {""} 
{"RSACng uses the NCrypt layer of CNG to do its work, and requires Windows Vista and the .NET Framework 3.5."} 
 {""} 
{"Example usage:"} {{
// Create an RSA-SHA256 signature using the key stored in "MyKey"
byte[]() dataToSign = Encoding.UTF8.GetBytes("Data to sign");
using (CngKey signingKey = CngKey.Open("MyKey");
using (RSACng rsa = new RSACng(signingKey))
{
    rsa.SignatureHashAlgorithm = CngAlgorithm.Sha256;
    return rsa.SignData(dataToSign);
}

}}
 {""} 
 {""} 

## APIs

### .ctor()

{"Create an RSACng algorithm with a random 2048 bit key pair."} 


### .ctor(int keySize)

{"Creates a new RSACng object that will use a randomly generated key of the specified size. Valid key sizes range from 384 to 16384 bits, in increments of 8. It's suggested that a minimum size of 2048 bits be used for all keys."} 

**Parameters:**
| keySize | {"size of hte key to generate, in bits"}  |

**Exceptions:**
| [System.Security.Cryptography.CryptographicException](http://msdn.microsoft.com/en-us/library/system.security.cryptography.cryptographicexception.aspx) | {"if"} _keySize_ {"is not valid"}  |


### .ctor([System.Security.Cryptography.CngKey](http://msdn.microsoft.com/en-us/library/system.security.cryptography.cngkey.aspx) key)

{"Creates a new RSACng object that will use the specified key. The key's"} [System.Security.Cryptography.CngKey.AlgorithmGroup](http://msdn.microsoft.com/en-us/library/system.security.cryptography.cngkey.algorithmgroup.aspx) {"must be Rsa."} 

**Parameters:**
| key | {"key to use for RSA operations"}  |

**Exceptions:**
| [System.ArgumentException](http://msdn.microsoft.com/en-us/library/system.argumentexception.aspx) | {"if"} _key_ {"is not an RSA key"}  |
| [System.ArgumentNullException](http://msdn.microsoft.com/en-us/library/system.argumentnullexception.aspx) | {"if"} _key_ {"is null"}  |


### [System.Security.Cryptography.CngAlgorithm](http://msdn.microsoft.com/en-us/library/system.security.cryptography.cngalgorithm.aspx) EncryptionHashAlgorithm { get; set; }

{"Sets the hash algorithm to use when encrypting or decrypting data using the OAEP padding method. This property is only used if data is encrypted or decrypted and the EncryptionPaddingMode is set to AsymmetricEncryptionPaddingMode.Oaep. The default value is Sha256."} 
**Exceptions:**
| [System.ArgumentNullException](http://msdn.microsoft.com/en-us/library/system.argumentnullexception.aspx) | {"if EncryptionHashAlgorithm is set to null"}  |



### [Security.Cryptography.AsymmetricPaddingMode](Security.Cryptography.AsymmetricPaddingMode) EncryptionPaddingMode { get; set; }

{"Sets the padding mode to use when encrypting or decrypting data. The default value is AsymmetricPaddingMode.Oaep."} 
**Exceptions:**
| [System.ArgumentNullException](http://msdn.microsoft.com/en-us/library/system.argumentnullexception.aspx) | {"if EncryptionPaddingMOde is set to null"}  |



### [System.Security.Cryptography.CngKey](http://msdn.microsoft.com/en-us/library/system.security.cryptography.cngkey.aspx) Key { get; }

{"Gets the key that will be used by the RSA object for any cryptographic operation that it uses. This key object will be disposed if the key is reset, for instance by changing the KeySize property, using ImportParamers to create a new key, or by Disposing of the parent RSA object. Therefore, you should make sure that the key object is no longer used in these scenarios. This object will not be the same object as the CngKey passed to the RSACng constructor if that constructor was used, however it will point at the same CNG key."} 
**Permission Requirements:**
| [System.Security.Permissions.SecurityPermission](http://msdn.microsoft.com/en-us/library/system.security.permissions.securitypermission.aspx) | {"SecurityPermission/UnmanagedCode is required to read this property."}  |


### [System.String](http://msdn.microsoft.com/en-us/library/system.string.aspx) KeyExchangeAlgorithm { get; }

{"Returns "RSA-PKCS1-KeyEx". This property should not be used."} 

### [System.Security.Cryptography.CngProvider](http://msdn.microsoft.com/en-us/library/system.security.cryptography.cngprovider.aspx) Provider { get; }

{"Key storage provider being used for the algorithm"} 

### [System.String](http://msdn.microsoft.com/en-us/library/system.string.aspx) SignatureAlgorithm { get; }

Returns "[http://www.w3.org/2000/09/xmldsig#rsa-sha1".](http://www.w3.org/2000/09/xmldsig#rsa-sha1".) This property should not be used. 

### [System.Security.Cryptography.CngAlgorithm](http://msdn.microsoft.com/en-us/library/system.security.cryptography.cngalgorithm.aspx) SignatureHashAlgorithm { get; set; }

{"Gets or sets the hash algorithm to use when signing or verifying data. The default value is Sha256."} 
**Exceptions:**
| [System.ArgumentNullException](http://msdn.microsoft.com/en-us/library/system.argumentnullexception.aspx) | {"if SignatureHashAlgorithm is set to null"}  |



### [Security.Cryptography.AsymmetricPaddingMode](Security.Cryptography.AsymmetricPaddingMode) SignaturePaddingMode { get; set; }

{"Gets or sets the padding mode to use when encrypting or decrypting data. The default value is AsymmetricPaddingMode.Pkcs1."} 
**Exceptions:**
| [System.ArgumentOutOfRangeException](http://msdn.microsoft.com/en-us/library/system.argumentoutofrangeexception.aspx) | {"if SignaturePaddingMode is set to a mode other than Pkcs1 or Pss"}  |



### int SignatureSaltBytes { get; set; }

{"Gets or sets the number of bytes of salt to use when signing data or verifying a signature using the PSS padding mode. This property is only used if data is being signed or verified and the SignaturePaddingMode is set to AsymmetricEncryptionPaddingMode.Pss. The default value is 20 bytes."} 
**Exceptions:**
| [System.ArgumentOutOfRangeException](http://msdn.microsoft.com/en-us/library/system.argumentoutofrangeexception.aspx) | {"if SignatureSaltBytes is set to a negative number"}  |



### [System.Security.Cryptography.RSAParameters](http://msdn.microsoft.com/en-us/library/system.security.cryptography.rsaparameters.aspx) ExportParameters(bool includePrivateParameters)

{"Exports the key used by the RSA object into an RSAParameters object."} 

**Parameters:**
| includePrivateParameters |  |

**Permission Requirements:**
| [System.Security.Permissions.KeyContainerPermission](http://msdn.microsoft.com/en-us/library/system.security.permissions.keycontainerpermission.aspx) | {"If the includePrivateParameters parameter is true and the CngKey is not ephemeral, KeyContainerPermission will be demanded."}  |


### void ImportParameters([System.Security.Cryptography.RSAParameters](http://msdn.microsoft.com/en-us/library/system.security.cryptography.rsaparameters.aspx) parameters)

{""} 
{"ImportParameters will replace the existing key that RSACng is working with by creating a new CngKey for the parameters structure. If the parameters structure contains only an exponent and modulus, then only a public key will be imported. If the parameters also contain P and Q values, then a full key pair will be imported."} 
 {""} 
{"The default KSP used by RSACng does not support importing full RSA key pairs on Windows Vista. If the ImportParameters method is called with a full key pair, the operation will fail with a CryptographicException stating that the operation was invalid. Other KSPs may have similar restrictions. To work around this, make sure to only import public keys when using the default KSP."} 
 {""} 

**Parameters:**
| parameters |  |

**Exceptions:**
| [System.ArgumentException](http://msdn.microsoft.com/en-us/library/system.argumentexception.aspx) | {"if"} _parameters_ {"contains neither an exponent nor a modulus"}  |
| [System.Security.Cryptography.CryptographicException](http://msdn.microsoft.com/en-us/library/system.security.cryptography.cryptographicexception.aspx) | {"if"} _parameters_ {"is not a valid RSA key or if"} _parameters_ {"is a full key pair and the default KSP is used"}  |


### System.Byte[]()() DecryptValue(System.Byte[]()() rgb)

{"DecryptValue decrypts the input data using the padding mode specified in the EncryptionPaddingMode property. The return value is the decrypted data."} 

**Parameters:**
| rgb | {"encrypted data to decrypt"}  |

**Exceptions:**
| [System.ArgumentNullException](http://msdn.microsoft.com/en-us/library/system.argumentnullexception.aspx) | {"if"} _rgb_ {"is null"}  |
| [System.Security.Cryptography.CryptographicException](http://msdn.microsoft.com/en-us/library/system.security.cryptography.cryptographicexception.aspx) | {"if"} _rgb_ {"could not be decrypted"}  |

**Permission Requirements:**
| [System.Security.Permissions.KeyContainerPermission](http://msdn.microsoft.com/en-us/library/system.security.permissions.keycontainerpermission.aspx) | {"This method requires KeyContainerPermission to the key in use if it is not ephemeral."}  |


### System.Byte[]()() EncryptValue(System.Byte[]()() rgb)

{"EncryptValue encrypts the input data using the padding mode specified in the EncryptionPaddingMode property. The return value is the encrypted data."} 

**Parameters:**
| rgb | {"data to encrypt"}  |

**Exceptions:**
| [System.ArgumentNullException](http://msdn.microsoft.com/en-us/library/system.argumentnullexception.aspx) | {"if"} _rgb_ {"is null"}  |
| [System.Security.Cryptography.CryptographicException](http://msdn.microsoft.com/en-us/library/system.security.cryptography.cryptographicexception.aspx) | {"if"} _rgb_ {"could not be decrypted"}  |


### System.Byte[]()() SignData(System.Byte[]()() data)

{"SignData signs the given data after hashing it with the SignatureHashAlgorithm algorithm."} 

**Parameters:**
| data | {"data to sign"}  |

**Exceptions:**
| [System.ArgumentNullException](http://msdn.microsoft.com/en-us/library/system.argumentnullexception.aspx) | {"if"} _data_ {"is null"}  |
| [System.Security.Cryptography.CryptographicException](http://msdn.microsoft.com/en-us/library/system.security.cryptography.cryptographicexception.aspx) | {"if"} _data_ {"could not be signed"}  |
| [System.InvalidOperationException](http://msdn.microsoft.com/en-us/library/system.invalidoperationexception.aspx) | {"if SignatureHashAlgorithm is not MD5, SHA-1, SHA-256, SHA-384, or SHA-512"}  |

**Permission Requirements:**
| [System.Security.Permissions.KeyContainerPermission](http://msdn.microsoft.com/en-us/library/system.security.permissions.keycontainerpermission.aspx) | {"This method will demand KeyContainerPermission if the key being used is not ephemeral."}  |


### System.Byte[]()() SignData(System.Byte[]()() data, int offset, int count)

{"SignData signs the given data after hashing it with the SignatureHashAlgorithm algorithm."} 

**Parameters:**
| data | {"data to sign"}  |
| offset | {"offset into the data that the signature should begin covering"}  |
| count | {"number of bytes to include in the signed data"}  |

**Exceptions:**
| [System.ArgumentNullException](http://msdn.microsoft.com/en-us/library/system.argumentnullexception.aspx) | {"if"} _data_ {"is null"}  |
| [System.ArgumentOutOfRangeException](http://msdn.microsoft.com/en-us/library/system.argumentoutofrangeexception.aspx) | {"if"} _offset_ {"or"} _count_ {"are negative, or if"} _count_ {"specifies more bytes than are available in"} _data_ {"."}  |
| [System.Security.Cryptography.CryptographicException](http://msdn.microsoft.com/en-us/library/system.security.cryptography.cryptographicexception.aspx) | {"if"} _data_ {"could not be signed"}  |
| [System.InvalidOperationException](http://msdn.microsoft.com/en-us/library/system.invalidoperationexception.aspx) | {"if SignatureHashAlgorithm is not MD5, SHA-1, SHA-256, SHA-384, or SHA-512"}  |

**Permission Requirements:**
| [System.Security.Permissions.KeyContainerPermission](http://msdn.microsoft.com/en-us/library/system.security.permissions.keycontainerpermission.aspx) | {"This method will demand KeyContainerPermission if the key being used is not ephemeral."}  |


### System.Byte[]() SignData([System.IO.Stream](http://msdn.microsoft.com/en-us/library/system.io.stream.aspx) data)

{"SignData signs the given data after hashing it with the SignatureHashAlgorithm algorithm."} 

**Parameters:**
| data | {"data to sign"}  |

**Exceptions:**
| [System.ArgumentNullException](http://msdn.microsoft.com/en-us/library/system.argumentnullexception.aspx) | {"if"} _data_ {"is null"}  |
| [System.Security.Cryptography.CryptographicException](http://msdn.microsoft.com/en-us/library/system.security.cryptography.cryptographicexception.aspx) | {"if"} _data_ {"could not be signed"}  |
| [System.InvalidOperationException](http://msdn.microsoft.com/en-us/library/system.invalidoperationexception.aspx) | {"if SignatureHashAlgorithm is not MD5, SHA-1, SHA-256, SHA-384, or SHA-512"}  |

**Permission Requirements:**
| [System.Security.Permissions.KeyContainerPermission](http://msdn.microsoft.com/en-us/library/system.security.permissions.keycontainerpermission.aspx) | {"This method will demand KeyContainerPermission if the key being used is not ephemeral."}  |


### System.Byte[]()() SignHash(System.Byte[]()() hash)

{"Sign data which was hashed using the SignatureHashAlgorithm; if the algorithm used to hash the data was different, use the SignHash(byte[](), CngAlgorithm) overload instead."} 

**Parameters:**
| hash | {"hash to sign"}  |

**Exceptions:**
| [System.ArgumentNullException](http://msdn.microsoft.com/en-us/library/system.argumentnullexception.aspx) | {"if"} _hash_ {"is null"}  |
| [System.Security.Cryptography.CryptographicException](http://msdn.microsoft.com/en-us/library/system.security.cryptography.cryptographicexception.aspx) | {"if"} _data_ {"could not be signed"}  |
| [System.InvalidOperationException](http://msdn.microsoft.com/en-us/library/system.invalidoperationexception.aspx) | {"if SignatureHashAlgorithm is not MD5, SHA-1, SHA-256, SHA-384, or SHA-512"}  |

**Permission Requirements:**
| [System.Security.Permissions.KeyContainerPermission](http://msdn.microsoft.com/en-us/library/system.security.permissions.keycontainerpermission.aspx) | {"This method will demand KeyContainerPermission if the key being used is not ephemeral."}  |


### System.Byte[]()() SignHash(System.Byte[]()() hash, [System.Security.Cryptography.CngAlgorithm](http://msdn.microsoft.com/en-us/library/system.security.cryptography.cngalgorithm.aspx) hashAlgorithm)

{"Sign already hashed data, specifying the algorithm it was hashed with. This method does not use the SignatureHashAlgorithm property."} 

**Parameters:**
| hash | {"hash to sign"}  |
| hashAlgorithm | {"algorithm"} _hash_ {"was signed with"}  |

**Exceptions:**
| [System.ArgumentNullException](http://msdn.microsoft.com/en-us/library/system.argumentnullexception.aspx) | {"if"} _hash_ {"or"} _hashAlgorithm_ {"are null"}  |
| [System.Security.Cryptography.CryptographicException](http://msdn.microsoft.com/en-us/library/system.security.cryptography.cryptographicexception.aspx) | {"if"} _data_ {"could not be signed"}  |

**Permission Requirements:**
| [System.Security.Permissions.KeyContainerPermission](http://msdn.microsoft.com/en-us/library/system.security.permissions.keycontainerpermission.aspx) | {"This method will demand KeyContainerPermission if the key being used is not ephemeral."}  |


### bool VerifyData(System.Byte[]()() data, System.Byte[]()() signature)

{"VerifyData verifies that the given signature matches given data after hashing it with the SignatureHashAlgorithm algorithm."} 

**Parameters:**
| data | {"data to verify"}  |
| signature | {"signature of the data"}  |

**Exceptions:**
| [System.ArgumentNullException](http://msdn.microsoft.com/en-us/library/system.argumentnullexception.aspx) | {"if"} _data_ {"or"} _signature_ {"are null"}  |
| [System.InvalidOperationException](http://msdn.microsoft.com/en-us/library/system.invalidoperationexception.aspx) | {"if SignatureHashAlgorithm is not MD5, SHA-1, SHA-256, SHA-384, or SHA-512"}  |

**Return Value:**
{"true if the signature verifies for the data, false if it does not"} 


### bool VerifyData(System.Byte[]()() data, int offset, int count, System.Byte[]()() signature)

{"VerifyData verifies that the given signature matches given data after hashing it with the SignatureHashAlgorithm algorithm."} 

**Parameters:**
| data | {"data to verify"}  |
| offset | {"offset into the data that the signature should begin covering"}  |
| count | {"number of bytes to include in the signed data"}  |
| signature | {"signature of the data"}  |

**Exceptions:**
| [System.ArgumentNullException](http://msdn.microsoft.com/en-us/library/system.argumentnullexception.aspx) | {"if"} _data_ {"or"} _signature_ {"are null"}  |
| [System.ArgumentOutOfRangeException](http://msdn.microsoft.com/en-us/library/system.argumentoutofrangeexception.aspx) | {"if"} _offset_ {"or"} _count_ {"are negative, or if"} _count_ {"specifies more bytes than are available in"} _data_ {"."}  |
| [System.InvalidOperationException](http://msdn.microsoft.com/en-us/library/system.invalidoperationexception.aspx) | {"if SignatureHashAlgorithm is not MD5, SHA-1, SHA-256, SHA-384, or SHA-512"}  |

**Return Value:**
{"true if the signature verifies for the data, false if it does not"} 


### bool VerifyData([System.IO.Stream](http://msdn.microsoft.com/en-us/library/system.io.stream.aspx) data, System.Byte[]() signature)

{"VerifyData verifies that the given signature matches given data after hashing it with the SignatureHashAlgorithm algorithm."} 

**Parameters:**
| data | {"data to verify"}  |
| signature | {"signature of the data"}  |

**Exceptions:**
| [System.ArgumentNullException](http://msdn.microsoft.com/en-us/library/system.argumentnullexception.aspx) | {"if"} _data_ {"or"} _signature_ {"are null"}  |
| [System.InvalidOperationException](http://msdn.microsoft.com/en-us/library/system.invalidoperationexception.aspx) | {"if SignatureHashAlgorithm is not MD5, SHA-1, SHA-256, SHA-384, or SHA-512"}  |

**Return Value:**
{"true if the signature verifies for the data, false if it does not"} 


### bool VerifyHash(System.Byte[]()() hash, System.Byte[]()() signature)

{"Verify data which was signed and already hashed with the SignatureHashAlgorithm; if a different hash algorithm was used to hash the data use the VerifyHash(byte[]()(), byte[]()(), CngAlgorithm) overload instead."} 

**Parameters:**
| hash | {"hash to verify"}  |
| signature | {"signature of the data"}  |

**Exceptions:**
| [System.ArgumentNullException](http://msdn.microsoft.com/en-us/library/system.argumentnullexception.aspx) | {"if"} _hash_ {"or"} _signature_ {"are null"}  |
| [System.InvalidOperationException](http://msdn.microsoft.com/en-us/library/system.invalidoperationexception.aspx) | {"if SignatureHashAlgorithm is not MD5, SHA-1, SHA-256, SHA-384, or SHA-512"}  |

**Return Value:**
{"true if the signature verifies for the hash, false if it does not"} 


### bool VerifyHash(System.Byte[]()() hash, System.Byte[]()() signature, [System.Security.Cryptography.CngAlgorithm](http://msdn.microsoft.com/en-us/library/system.security.cryptography.cngalgorithm.aspx) hashAlgorithm)

{"Verify data which was signed and hashed with the given hash algorithm. This overload does not use the SignatureHashAlgorithm property."} 

**Parameters:**
| hash | {"hash to verify"}  |
| signature | {"signature of the data"}  |
| hashAlgorithm | {"algorithm that"} _hash_ {"was hashed with"}  |

**Exceptions:**
| [System.ArgumentNullException](http://msdn.microsoft.com/en-us/library/system.argumentnullexception.aspx) | {"if"} _hash_ {","} _signature_ {", or"} _hashAlgorithm_ {"are null"}  |

**Return Value:**
{"true if the signature verifies for the hash, false if it does not"} 


