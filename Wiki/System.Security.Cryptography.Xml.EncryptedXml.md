# System.Security.Cryptography.Xml.EncryptedXml

{"The EncryptedXmlExtension methods type provides several extension methods for the"} [System.Security.Cryptography.Xml.EncryptedXml](http://msdn.microsoft.com/en-us/library/system.security.cryptography.xml.encryptedxml.aspx) {"class. This type is in the Security.Cryptography.Xml namespace (not the System.Security.Cryptography.Xml namespace), so in order to use these extension methods, you will need to make sure you include this namespace as well as a reference to Security.Cryptography.dll."} 

## APIs

### void ReplaceData2([System.Xml.XmlElement](http://msdn.microsoft.com/en-us/library/system.xml.xmlelement.aspx) inputElement, System.Byte[]() decryptedData)

{"Replace the XML element with the decrypted data. This method works very much like the standard"} [System.Security.Cryptography.Xml.EncryptedXml.ReplaceData(System.Xml.XmlElement,System.Byte(array))](http://msdn.microsoft.com/en-us/library/system.security.cryptography.xml.encryptedxml.replacedata.aspx) {"API, with one exception. If inputElement is the root element of an XML document, ReplaceData2 will ensure that any other top-level XML items (such as the XML declaration) will not be overwritten, whereas ReplaceData always overwrites the entire XML document with the decrypted data."} 



