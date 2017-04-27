# Security.Cryptography.X509Certificates.X509AlternateName

{"The X509Alternate name type represents alternate name information pulled from an X509 certificate's subject or issuer alternate names extension. This type serves as the base for the more specific alternate name types which can contain more detailed data about the name."} 

## APIs

### .ctor([Security.Cryptography.X509Certificates.AlternateNameType](Security.Cryptography.X509Certificates.AlternateNameType) type)

{"Construct an empty X509AlternateName of the specified type"} 

**Parameters:**
| type |  |


### [Security.Cryptography.X509Certificates.AlternateNameType](Security.Cryptography.X509Certificates.AlternateNameType) AlternateNameType { get; }

{"Get the type of alternate name this object represents"} 

### [System.Object](http://msdn.microsoft.com/en-us/library/system.object.aspx) AlternateName { get; }

{"Get the alternate name that this object represents. The type of object returned from this property depends upon how the specific alternate name type specifies its data. Strongly typed alternate name data can also be obtained from working with the subtypes directly."} 

