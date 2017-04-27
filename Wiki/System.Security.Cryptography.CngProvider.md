# System.Security.Cryptography.CngProvider

{""} 
{"The CngProviderExtensionMethods type provides several extension methods for the"} [System.Security.Cryptography.CngProvider](http://msdn.microsoft.com/en-us/library/system.security.cryptography.cngprovider.aspx) {"class. This type is in the Security.Cryptography namespace (not the System.Security.Cryptography namespace), so in order to use these extension methods, you will need to make sure you include this namespace as well as a reference to Security.Cryptography.dll"} 
 {""} 
{"CngProvider uses the NCrypt layer of CNG, and requires Windows Vista and the .NET Framework 3.5."} 
 {""} 

## APIs

### System.Collections.Generic.IEnumerable<[System.Security.Cryptography.CngKey](http://msdn.microsoft.com/en-us/library/system.security.cryptography.cngkey.aspx)> GetKeys()

{"GetKeys provides an enumerator over all of the keys that are stored in the key storage provider."} 


### System.Collections.Generic.IEnumerable<[System.Security.Cryptography.CngKey](http://msdn.microsoft.com/en-us/library/system.security.cryptography.cngkey.aspx)> GetKeys([System.Security.Cryptography.CngKeyOpenOptions](http://msdn.microsoft.com/en-us/library/system.security.cryptography.cngkeyopenoptions.aspx) openOptions)

{"GetKeys provides an enumerator over all of the keys that are stored in the key storage provider. This overload of GetKeys allows you to enumerate over only the user keys in the KSP or only the machine keys."} 

**Parameters:**
| openOptions | {"options to use when opening the CNG keys"}  |


### System.Collections.Generic.IEnumerable<[System.Security.Cryptography.CngKey](http://msdn.microsoft.com/en-us/library/system.security.cryptography.cngkey.aspx)> GetKeys([System.Security.Cryptography.CngKeyOpenOptions](http://msdn.microsoft.com/en-us/library/system.security.cryptography.cngkeyopenoptions.aspx) openOptions, [System.Security.Cryptography.CngAlgorithm](http://msdn.microsoft.com/en-us/library/system.security.cryptography.cngalgorithm.aspx) algorithm)

{"GetKeys provides an enumerator over all of the keys that are stored in the key storage provider. This overload of GetKeys allows you to enumerate over only the user keys in the KSP or only the machine keys. It also allows you to return only keys that are usable with a specified algorithm."} 

**Parameters:**
| openOptions | {"options to use when opening the CNG keys"}  |
| algorithm | {"algorithm that the returned keys should support"}  |

**Exceptions:**
| [System.ArgumentNullException](http://msdn.microsoft.com/en-us/library/system.argumentnullexception.aspx) | {"if"} _algorithm_ {"is null"}  |


### System.Collections.Generic.IEnumerable<[System.Security.Cryptography.CngAlgorithm](http://msdn.microsoft.com/en-us/library/system.security.cryptography.cngalgorithm.aspx)> GetSupportedAlgorithms()

{"GetSupportedAlgorithms provides an enumerator over all of the algorithms that the NCrypt provider supports."} 


### System.Collections.Generic.IEnumerable<[System.Security.Cryptography.CngAlgorithm](http://msdn.microsoft.com/en-us/library/system.security.cryptography.cngalgorithm.aspx)> GetSupportedAlgorithms([Security.Cryptography.NCryptAlgorithmOperations](Security.Cryptography.NCryptAlgorithmOperations) operations)

{"GetSupportedAlgorithms provides an enumerator over all of the algorithms that the NCrypt provider supports. Each of the returned algortihms will support at least one of the cryptographic operations specified by the operations parameter."} 

**Parameters:**
| operations | {"operations that the returned algorithms should support"}  |


### [Microsoft.Win32.SafeHandles.SafeNCryptProviderHandle](http://msdn.microsoft.com/en-us/library/microsoft.win32.safehandles.safencryptproviderhandle.aspx) OpenProvider()

{"Gets a SafeHandle for the NCrypt provider. This handle can be used for P/Invoking to other APIs which expect an NCRYPT_PROV_HANDLE parameter."} 

**Permission Requirements:**
| [System.Security.Permissions.SecurityPermission](http://msdn.microsoft.com/en-us/library/system.security.permissions.securitypermission.aspx) | {"SecurityPermission/UnmanagedCode is required of the immediate caller to this API"}  |


