# Security.Cryptography.TripleDESCng

{""} 
{"The TripleDESCng class provides a wrapper for the CNG implementation of the 3DES algorithm. It provides the same interface as the"} [System.Security.Cryptography.TripleDESCryptoServiceProvider](http://msdn.microsoft.com/en-us/library/system.security.cryptography.tripledescryptoserviceprovider.aspx) {"implementation shipped with the .NET Framework."} 
 {""} 
{"TripleDESCng uses the BCrypt layer of CNG to do its work, and requires Windows Vista and the .NET Framework 3.5."} 
 {""} 
{"Since most of the TripleDESCng APIs are inherited from the"} [System.Security.Cryptography.TripleDES](http://msdn.microsoft.com/en-us/library/system.security.cryptography.tripledes.aspx) {"base class, please see the MSDN documentation for TripleDES for a complete description."} 
 {""} 

## APIs

### .ctor()

{"Constructs a TripleDESCng object. The default settings for this object are:"} 
* {"Algorithm provider - Microsoft Primitive Algorithm Provider"} 
* {"Block size - 64 bits"} 
* {"Feedback size - 64 bits"} 
* {"Key size - 192 bits"} 
* {"Cipher mode - CipherMode.CBC"} 
* {"Padding mode - PaddingMode.PKCS7"} 
 {""} 


### .ctor([System.Security.Cryptography.CngProvider](http://msdn.microsoft.com/en-us/library/system.security.cryptography.cngprovider.aspx) algorithmProvider)

{"Constructs a TripleDESCng object which uses the specified algorithm provider. The default settings for this object are:"} 
* {"Block size - 64 bits"} 
* {"Feedback size - 64 bits"} 
* {"Key size - 192 bits"} 
* {"Cipher mode - CipherMode.CBC"} 
* {"Padding mode - PaddingMode.PKCS7"} 
 {""} 

**Parameters:**
| algorithmProvider | {"algorithm provider to use for 3DES computation"}  |

**Exceptions:**
| [System.ArgumentNullException](http://msdn.microsoft.com/en-us/library/system.argumentnullexception.aspx) | {"if"} _algorithmProvider_ {"is null"}  |


### [System.Security.Cryptography.CipherMode](http://msdn.microsoft.com/en-us/library/system.security.cryptography.ciphermode.aspx) Mode { get; set; }

{"Gets or sets the cipher mode to use during encryption or decryption. Supported modes are:"} 
* {"CipherMode.CBC"} 
* {"CipherMode.ECB"} 
* {"CipherMode.CFB"} 
 {""} 

