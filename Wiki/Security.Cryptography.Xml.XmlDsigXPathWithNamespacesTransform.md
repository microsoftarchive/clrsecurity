# Security.Cryptography.Xml.XmlDsigXPathWithNamespacesTransform

{""} 
{"XmlDsigXPathWithNamespacesTransform provides a version of the XPath transform which allows the XPath expression to use the namespace mappings in scope at the point of the XML declaration of the XPath expression. The standard XmlDsigXPathTransform requires that any namespaces being used in the XPath expression be defined on the XPath node explicitly. This version of the transform allows any namepsace in scope at the XPath node to be used, even if they are not explicitly declared on the node itself."} 
 {""} 
{"In order to use this transform when signing, simply add it to the Reference section that should be processed with the XPath expression. For example:"} 
 {""} {{
Reference reference = new Reference("");
reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
            
// Ensure that we can use the clrsec namespace in the XPath expression
Dictionary<string, string> additionalNamespaces = new Dictionary<string, string>();
additionalNamespaces ["clrsec"](_clrsec_) = "http://www.codeplex.com/clrsecurity";
reference.AddTransform(new XmlDsigXPathWithNamespacesTransform("ancestor-or-self::node()[@clrsec:sign='true'](@clrsec_sign='true')", null, additionalNamespaces));

}}
 {""} 
{"For verification purposes, machine.config must be setup to map the XPath transform URL to XmlDsigXPathWithNamespacesTransform so that SignedXml creates this version of the XPath transform when processing a signature."} 
 {""} 
{"Registration in CryptoConfig requires editing the machine.config file found in the .NET Framework installation's configuration directory (such as %WINDIR%\Microsoft.NET\Framework\v2.0.50727\Config or %WINDIR%\Microsoft.NET\Framework64\v2.0.50727\Config) to include registration information on the type. For example:"} 
 {""} {{
<configuration>
  <mscorlib>
    <cryptographySettings>
      <cryptoNameMapping>
        <cryptoClasses>
          <cryptoClass XmlDsigXPathWithNamespacesTransform="Security.Cryptography.Xml.XmlDsigXPathWithNamespacesTransform, Security.Cryptography, Version=1.4.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35" />
        </cryptoClasses>
        <nameEntry name="http://www.w3.org/TR/1999/REC-xpath-19991116" class="XmlDsigXPathWithNamespacesTransform" />
      </cryptoNameMapping>
    </cryptographySettings>
  </mscorlib>
</configuration>    

}}
 {""} 
{"After adding this registration entry, the assembly which contains the XmlDsigXPathWithNamespacesTransform (in the example above Security.Cryptography.dll) needs to be added to the GAC."} 
 {""} 
{"Note that on 64 bit machines, both the Framework and Framework64 machine.config files should be updated, and if the signature description assembly is built bit-specific it needs to be added to both the 32 and 64 bit GACs."} 
 {""} 
See [http://www.w3.org/TR/xmldsig-core/#sec-XPath](http://www.w3.org/TR/xmldsig-core/#sec-XPath) for more information on the XPath transform. 
 {""} 
{"Since most of the XmlDsigXPathWithNamespacesTransform APIs are inherited from the"} [System.Security.Cryptography.Xml.XmlDsigXPathTransform](http://msdn.microsoft.com/en-us/library/system.security.cryptography.xml.xmldsigxpathtransform.aspx) {"base class, please see the MSDN documentation for XmlDsigXPathTransform for a complete list of the methods and properties available on XmlDsigXPathWithNamespacesTransform."} 
 {""} 

## APIs

### .ctor()

{"Constructs an XmlDsigXPathWithNamespacesTransform object without an initial XPath query or namespaces. This constructor should not be used, and is provided so that the type may be instantiated from CryptoConfig."} 


### .ctor([System.String](http://msdn.microsoft.com/en-us/library/system.string.aspx) xpath)

{"Constructs an XmlDsigXPathWithNamespacesTransform object which will apply the given XPath expression when it is invoked. No XML namespaces will be brought into scope for use in the query."} 

**Parameters:**
| xpath | {"xpath expression to use in this transform"}  |

**Exceptions:**
| [System.ArgumentNullException](http://msdn.microsoft.com/en-us/library/system.argumentnullexception.aspx) | {"if"} _xpath_ {"is null"}  |


### void LoadInnerXml([System.Xml.XmlNodeList](http://msdn.microsoft.com/en-us/library/system.xml.xmlnodelist.aspx) nodeList)

{"Build a transform from its XML representation"} 

**Parameters:**
| nodeList |  |


### void LoadInput([System.Object](http://msdn.microsoft.com/en-us/library/system.object.aspx) obj)

{"Load input nodes to process"} 

**Parameters:**
| obj |  |


### [System.Object](http://msdn.microsoft.com/en-us/library/system.object.aspx) GetOutput()

{"Get the output of running the XPath expression on the input nodes"} 


