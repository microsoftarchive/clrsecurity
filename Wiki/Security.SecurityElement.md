# System.Security.SecurityElement

SecurityElementExtensionMehods provides several extension methods for the [System.Security.SecurityElement](http://msdn.microsoft.com/en-us/library/system.security.securityelement.aspx) class. This type is in the Security namespace (not the System.Security namespace), so in order to use these extension methods, you will need to make sure you include this namespace as well as a reference to Security.dll. 

## APIs

### [System.Xml.XmlElement](http://msdn.microsoft.com/en-us/library/system.xml.xmlelement.aspx) ToXmlElement()

Convert a SecurityElement XML tree to an equivilent tree in the System.Xml object model 


### [System.Xml.XmlElement](http://msdn.microsoft.com/en-us/library/system.xml.xmlelement.aspx) ToXmlElement([System.Xml.XmlDocument](http://msdn.microsoft.com/en-us/library/system.xml.xmldocument.aspx) containingDocument)

Convert a SecurityElement XML tree to an equivilent tree in the System.Xml object model 

**Parameters:**
| containingDocument | XML document to create the XML tree from  |

**Exceptions:**
| [System.ArgumentNullException](http://msdn.microsoft.com/en-us/library/system.argumentnullexception.aspx) | if _containingDocument_ is null  |


### bool XmlEquals([System.Security.SecurityElement](http://msdn.microsoft.com/en-us/library/system.security.securityelement.aspx) rhs)

Perform a case-senstive comparsion of the content of two security elements 

**Parameters:**
| rhs | SecurityElement to compare against  |

**Exceptions:**
| [System.ArgumentNullException](http://msdn.microsoft.com/en-us/library/system.argumentnullexception.aspx) | if _rhs_ is null  |


### bool XmlEquals([System.Security.SecurityElement](http://msdn.microsoft.com/en-us/library/system.security.securityelement.aspx) rhs, [System.StringComparison](http://msdn.microsoft.com/en-us/library/system.stringcomparison.aspx) comparisonType)

Perform a comparison of the content of two security elements 

**Parameters:**
| rhs | SecurityElement to compare against  |
| comparisonType | type of comparison to perform  |

**Exceptions:**
| [System.ArgumentNullException](http://msdn.microsoft.com/en-us/library/system.argumentnullexception.aspx) | if _rhs_ is null  |
