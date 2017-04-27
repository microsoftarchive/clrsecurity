# Security.Cryptography.CryptoConfig2

{""} 
{".NET v3.5 added some new crypto algorithms in System.Core.dll, however due to layering restrictions CryptoConfig does not have registration entries for these algorithms. Similarly, CryptoConfig does not know about any of the algorithms added in this assembly."} 
 {""} 
{"CryptoConfig2 wraps the CryptoConfig.Create method, allowing it to also create System.Core and Microsoft.Security.Cryptography algorithm objects."} 
 {""} 
{"CryptoConfig2 requires the .NET Framework 3.5."} 
 {""} 

## APIs

### static void AddAlgorithm([System.Type](http://msdn.microsoft.com/en-us/library/system.type.aspx) algorithm, System.String[]() aliases)

{""} 
{"AddAlgorithm allows an application to register a new algorithm with CryptoConfig2 in the current AppDomain. The algorithm is then creatable via calling"} [Security.Cryptography.CryptoConfig2](Security.Cryptography.CryptoConfig2).CreateFromName(System.String) {"and supplying one of:"} 
 {""} 
* {"The name of the algorithm type"} 
* {"The namespace qualified name of the algorithm type"} 
* {"Any of the aliases supplied for the type"} 
 {""} 
{"This registration is valid only in the AppDomain that does the registration, and is not persisted. The registered algorithm will only be creatable via CryptoConfig2 and not via standard"} [System.Security.Cryptography.CryptoConfig](http://msdn.microsoft.com/en-us/library/system.security.cryptography.cryptoconfig.aspx) {"."} 
 {""} 
{"All algorithms registered with CryptoConfig2 must have a default constructor, or they wil not be creatable at runtime."} 
 {""} 
{"This method is thread safe."} 
 {""} 

**Parameters:**
| algorithm | {"type to register with CryptoConfig2"}  |
| aliases | {"list of additional aliases which can create the type"}  |

**Exceptions:**
| [System.ArgumentNullException](http://msdn.microsoft.com/en-us/library/system.argumentnullexception.aspx) | {"if"} _algorithm_ {"or"} _aliases_ {"are null"}  |
| [System.InvalidOperationException](http://msdn.microsoft.com/en-us/library/system.invalidoperationexception.aspx) | {"if an alias is either null, empty, or a duplicate of an existing registered alias"}  |

**Permission Requirements:**
| [System.Security.PermissionSet](http://msdn.microsoft.com/en-us/library/system.security.permissionset.aspx) | {"The immediate caller of this API must be fully trusted"}  |


### static System.Func<[System.Object](http://msdn.microsoft.com/en-us/library/system.object.aspx)> CreateFactoryFromName([System.String](http://msdn.microsoft.com/en-us/library/system.string.aspx) name)

{""} 
{"CreateFactoryFromName is similar to"} [Security.Cryptography.CryptoConfig2](Security.Cryptography.CryptoConfig2).CreateFromName(System.String) {", except that intsead of returning a single instance of a crypto algorithm, CreateFactoryFromName returns a function that can create new instances of the algorithm. This function will be more efficient to use if multiple intsances of the same algorithm are needed than calling CreateFromName repeatedly."} 
 {""} 
{"Name comparisons are case insensitive."} 
 {""} 
{"This method is thread safe."} 
 {""} 

**Parameters:**
| name | {"name of the algorithm to create a factory for"}  |

**Exceptions:**
| [System.ArgumentNullException](http://msdn.microsoft.com/en-us/library/system.argumentnullexception.aspx) | {"if"} _name_ {"is null"}  |


### static [System.Object](http://msdn.microsoft.com/en-us/library/system.object.aspx) CreateFromName([System.String](http://msdn.microsoft.com/en-us/library/system.string.aspx) name)

{""} 
{"CreateFromName attempts to map the given algorithm name into an instance of the specified algorithm. It works with both the built in algorithms in the .NET Framework 3.5 as well as the algorithms in the Security.Cryptography.dll assembly. Since it does work with the built in crypto types, CryptoConfig2.CreateFromName can be used as a drop-in replacement for"} [System.Security.Cryptography.CryptoConfig.CreateFromName(System.String)](http://msdn.microsoft.com/en-us/library/system.security.cryptography.cryptoconfig.createfromname.aspx) {""} 
 {""} 
{"Types in System.Core.dll and Security.Cryptography.dll can be mapped either by their simple type name or their namespace type name. For example, AesCng and Security.Cryptography.AesCng will both create an instance of the"} [Security.Cryptography.AesCng](Security.Cryptography.AesCng) {"type. Additionally, the following names are also given mappings in CryptoConfig2:"} 
 {""} 
* {"AES -"} [System.Security.Cryptography.AesCryptoServiceProvider](http://msdn.microsoft.com/en-us/library/system.security.cryptography.aescryptoserviceprovider.aspx) 
* {"ECDsa -"} [System.Security.Cryptography.ECDsaCng](http://msdn.microsoft.com/en-us/library/system.security.cryptography.ecdsacng.aspx) 
* {"ECDH -"} [System.Security.Cryptography.ECDiffieHellmanCng](http://msdn.microsoft.com/en-us/library/system.security.cryptography.ecdiffiehellmancng.aspx) 
* {"ECDiffieHellman -"} [System.Security.Cryptography.ECDiffieHellmanCng](http://msdn.microsoft.com/en-us/library/system.security.cryptography.ecdiffiehellmancng.aspx) 
 {""} 
{"Name comparisons are case insensitive."} 
 {""} 
{"This method is thread safe."} 
 {""} 

**Parameters:**
| name | {"name of the algorithm to create"}  |

**Exceptions:**
| [System.ArgumentNullException](http://msdn.microsoft.com/en-us/library/system.argumentnullexception.aspx) | {"if"} _name_ {"is null"}  |


