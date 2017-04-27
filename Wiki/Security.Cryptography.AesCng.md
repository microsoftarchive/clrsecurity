# Security.Cryptography.AesCng

{""} 
{"The AesCng class provides a wrapper for the CNG implementation of the AES algorithm. It provides the same interface as the other AES implementations shipped with the .NET Framework, including"} [System.Security.Cryptography.AesManaged](http://msdn.microsoft.com/en-us/library/system.security.cryptography.aesmanaged.aspx) {"and"} [System.Security.Cryptography.AesCryptoServiceProvider](http://msdn.microsoft.com/en-us/library/system.security.cryptography.aescryptoserviceprovider.aspx) {"."} 
 {""} 
{"AesCng uses the BCrypt layer of CNG to do its work, and requires Windows Vista and the .NET Framework 3.5."} 
 {""} 
{"Since most of the AesCng APIs are inherited from the"} [System.Security.Cryptography.Aes](http://msdn.microsoft.com/en-us/library/system.security.cryptography.aes.aspx) {"base class, see the documentation for Aes for a complete API description."} 
 {""} 

## APIs

### .ctor([System.Security.Cryptography.CngProvider](http://msdn.microsoft.com/en-us/library/system.security.cryptography.cngprovider.aspx) algorithmProvider)

{"Constructs an AesCng object using the specified algorithm provider. The default settings for this object are:"} 
* {"Algorithm provider - Microsoft Primitive Algorithm Provider"} 
* {"Block size - 128 bits"} 
* {"Feedback size - 8 bits"} 
* {"Key size - 256 bits"} 
* {"Cipher mode - CipherMode.CBC"} 
* {"Padding mode - PaddingMode.PKCS7"} 
 {""} 

**Parameters:**
| algorithmProvider | {"algorithm provider to use for AES computation"}  |

**Exceptions:**
| [System.ArgumentNullException](http://msdn.microsoft.com/en-us/library/system.argumentnullexception.aspx) | {"if"} _algorithmProvider_ {"is null"}  |


### [System.Security.Cryptography.CipherMode](http://msdn.microsoft.com/en-us/library/system.security.cryptography.ciphermode.aspx) Mode { get; set; }

{"Gets or sets the cipher mode to use during encryption or decryption. Supported modes are:"} 
* {"CipherMode.CBC"} 
* {"CipherMode.ECB"} 
* {"CipherMode.CFB"} 
 {""} 

