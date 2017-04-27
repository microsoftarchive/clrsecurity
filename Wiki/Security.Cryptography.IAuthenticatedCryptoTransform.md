# Security.Cryptography.IAuthenticatedCryptoTransform

{"Interface for crypto transforms that support generating an authentication tag."} 

## APIs

### System.Byte[]() GetTag()

{"Get the authentication tag produced by the transform. This is only valid in the encryption case and only after the final block has been transformed."} 

**Exceptions:**
| [System.InvalidOperationException](http://msdn.microsoft.com/en-us/library/system.invalidoperationexception.aspx) | {"If the crypto transform is a decryptor, or if the final block has not yet been transformed."}  |


