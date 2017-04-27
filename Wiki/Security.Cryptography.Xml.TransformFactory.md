# Security.Cryptography.Xml.TransformFactory

{"The TransformFactory class provides helper methods for programmatically creating transforms for use with the"} [System.Security.Cryptography.Xml.SignedXml](http://msdn.microsoft.com/en-us/library/system.security.cryptography.xml.signedxml.aspx) {"class. Since many of the transforms do not have constructors or other method that allow them to be created easily in code when creating an XML signature, they generally have to be constructed via XML. TransformFactory provides APIs that allow you to create these transforms without having to directly create the XML for the transform by hand."} 

## APIs

### static [System.Security.Cryptography.Xml.XmlDsigXPathTransform](http://msdn.microsoft.com/en-us/library/system.security.cryptography.xml.xmldsigxpathtransform.aspx) CreateXPathTransform([System.String](http://msdn.microsoft.com/en-us/library/system.string.aspx) xpath)

{"Creates an XPath transform for the given XPath query. The transform created from this method does not bring any XML namespaces into scope, so the XPath query must not rely on any XML namespaces from the XML being signed."} 

**Parameters:**
| xpath | {"XPath query to embed into the transform"}  |

**Exceptions:**
| [System.ArgumentNullException](http://msdn.microsoft.com/en-us/library/system.argumentnullexception.aspx) | {"if"} _xpath_ {"is null"}  |


