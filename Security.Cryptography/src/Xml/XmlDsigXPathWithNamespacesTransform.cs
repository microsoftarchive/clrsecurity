// Copyright (c) Microsoft Corporation.  All rights reserved.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.IO;
using System.Security.Cryptography.Xml;
using System.Xml;
using System.Xml.XPath;
using Security.Cryptography.Properties;

namespace Security.Cryptography.Xml
{
    /// <summary>
    ///     XmlDsigXPathWithNamespacesTransform provides a version of the XPath transform which allows the
    ///     XPath expression to use the namespace mappings in scope at the point of the XML declaration of the
    ///     XPath expression.  The standard XmlDsigXPathTransform requires that any namespaces being used in
    ///     the XPath expression be defined on the XPath node explicitly.  This version of the transform
    ///     allows any namepsace in scope at the XPath node to be used, even if they are not explicitly
    ///     declared on the node itself.
    ///     
    ///     In order to use this transform when signing, simply add it to the Reference section that should
    ///     be processed with the XPath expression.  For verification purposes, machine.config must be edited
    ///     so that SignedXml creates this version of the XPath transform when processing a signature.
    ///     
    ///     This transform can be registered in machine.config in a section similar to:
    ///     <example>
    ///         <![CDATA[
    ///           <configuration>
    ///             <mscorlib>
    ///               <cryptographySettings>
    ///                 <cryptoNameMapping>
    ///                   <cryptoClasses>
    ///                     <cryptoClass XmlDsigXPathWithNamespacesTransform="Security.Cryptography.Xml.XmlDsigXPathWithNamespacesTransform, Security.Cryptography, Version=1.4.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35" />
    ///                   </cryptoClasses>
    ///                   <nameEntry name="http://www.w3.org/TR/1999/REC-xpath-19991116" class="XmlDsigXPathWithNamespacesTransform" />
    ///                 </cryptoNameMapping>
    ///               </cryptographySettings>
    ///             </mscorlib>
    ///           </configuration>    
    ///         ]]>
    ///     </example>
    ///     See http://www.w3.org/TR/xmldsig-core/#sec-XPath for more information on the XPath transform.
    /// </summary>
    [SuppressMessage("Microsoft.Naming", "CA1702:CompoundWordsShouldBeCasedCorrectly", MessageId = "XPath", Justification = "This matches the XPath spelling in the rest of the framework.")]
    public sealed class XmlDsigXPathWithNamespacesTransform : XmlDsigXPathTransform
    {
        private XmlDocument m_inputNodes;
        private IDictionary<string, string> m_namespaces;
        private string m_xpathExpression;

        public XmlDsigXPathWithNamespacesTransform()
        {
        }

        /// <summary>
        ///     Create a transform for a specific XPath expressin which does not need any additional XML
        ///     namespaces in scope.
        /// </summary>
        public XmlDsigXPathWithNamespacesTransform(string xpath) : this(xpath, null)
        {
        }

        /// <summary>
        ///     Create a transform for a specific XPath expression which will explicitly bring some
        ///     namepsace mappings into scope for the query.  These namespacse will be added to the XPath
        ///     expression node in the produced XML, and are therefore guaranteed to be in scope when the
        ///     query runs in the verification process.
        /// </summary>
        public XmlDsigXPathWithNamespacesTransform(string xpath,
                                                   IDictionary<string, string> explicitNamespaces)
            : this(xpath, explicitNamespaces, null)
        {
        }

        /// <summary>
        ///     Create a transform for a specific XPath expression with namespace mappings available for the
        ///     expression to use.  Explicit namespaces are directly added to the XPath element of the
        ///     transform, and will appear in the produced XML (guaranteeing that they will be visible when
        ///     the transform runs in the verification process).  Additional namespaces will not be added to
        ///     the transform XML itself, and will be required to be in scope of the XPath node in the XML
        ///     when the verification process runs.
        /// </summary>
        public XmlDsigXPathWithNamespacesTransform(string xpath,
                                                   IDictionary<string, string> explicitNamespaces,
                                                   IDictionary<string, string> additionalNamespaces)
        {
            if (xpath == null)
                throw new ArgumentNullException("xpath");

            // Although we could initialize ourselves directly, there's no good way to initialize the base
            // XPath transform without going through XML.  Since we can also initialize via XML, we will
            // just piggyback on that to keep all initialization code centralized.
            XmlDocument doc = new XmlDocument();

            XmlElement rootElement = doc.CreateElement("XPathRoot");

            // Put the additional namespaces on a root element of the XPath element, so that we don't add them
            // to the XML that will be generated for this transform.  We need to put them on a parent node
            // so that they are in scope for signautre generation when the XPath node isn't yet attached to
            // its context document.
            if (additionalNamespaces != null)
            {
                foreach (string namespaceAlais in additionalNamespaces.Keys)
                {
                    XmlAttribute namespaceDeclaration = doc.CreateAttribute("xmlns",
                                                                            namespaceAlais,
                                                                            "http://www.w3.org/2000/xmlns/");
                    namespaceDeclaration.Value = additionalNamespaces[namespaceAlais];
                    rootElement.Attributes.Append(namespaceDeclaration);
                }
            }

            XmlElement xpathElement = doc.CreateElement("XPath");
            xpathElement.InnerText = xpath;

            // Explicit namespaces need to be added directly to the XPath node itself so that they end up in
            // the produced XML.
            if (explicitNamespaces != null)
            {
                foreach (string namespaceAlais in explicitNamespaces.Keys)
                {
                    XmlAttribute namespaceDeclaration = doc.CreateAttribute("xmlns",
                                                                            namespaceAlais,
                                                                            "http://www.w3.org/2000/xmlns/");
                    namespaceDeclaration.Value = explicitNamespaces[namespaceAlais];
                    xpathElement.Attributes.Append(namespaceDeclaration);
                }
            }

            rootElement.AppendChild(xpathElement);

            LoadInnerXml(xpathElement.SelectNodes("."));
        }

        /// <summary>
        ///     Build a transform from its XML representation
        /// </summary>
        public override void LoadInnerXml(XmlNodeList nodeList)
        {
            base.LoadInnerXml(nodeList);

            // XmlDSigXPathTransform.LoadInput will thow on null input
            Debug.Assert(nodeList != null, "nodeList != null");

            // XmlDsigXpathTransform does not expose the XPath expression or the namespaces that are added
            // on the XPath node itself, so we need to look for them ourselves.
            for (int i = 0; i < nodeList.Count && m_xpathExpression == null; ++i)
            {
                // Only look for XPath elements
                XmlElement currentElement = nodeList[i] as XmlElement;
                if (currentElement != null && String.Equals(currentElement.LocalName, "XPath", StringComparison.Ordinal))
                {
                    // The XPath expression is the inner text of the XPath node
                    m_xpathExpression = currentElement.InnerXml.Trim();

                    // Get any namespace mappings in scope for the XPath element so that we can use those
                    // when the XPath is evaluated.
                    m_namespaces = currentElement.CreateNavigator().GetNamespacesInScope(XmlNamespaceScope.All);
                }
            }

            // XmlDSigXPathTransform should have failed when loading it's inner XML if we did not have an
            // inner XPath expression, which means if we got here we should have also been able to find the
            // expression.
            Debug.Assert(m_xpathExpression != null, "m_xpathExpression != null");
        }

        /// <summary>
        ///     Load input nodes to process
        /// </summary>
        public override void LoadInput(object obj)
        {
            if (obj == null)
                throw new ArgumentNullException("obj");

            // Canonicalize the input into a stream
            XmlDsigC14NTransform canonicalization = new XmlDsigC14NTransform(true);
            canonicalization.LoadInput(obj);
            Stream canonicalizedInput = canonicalization.GetOutput(typeof(Stream)) as Stream;

            // Load the canonicalized input into a document to transform
            XmlDocument document = new XmlDocument();
            document.Load(canonicalizedInput);
            m_inputNodes = document;
        }

        /// <summary>
        ///     Get the output of running the XPath expression on the input nodes
        /// </summary>
        public override object GetOutput()
        {
            XmlDSigNodeList outputNodes = new XmlDSigNodeList();

            // Only do work if we've been loaded with both an XPath expression as well as a list of input
            // nodes to transform
            if (m_xpathExpression != null && m_inputNodes != null)
            {
                XPathNavigator navigator = m_inputNodes.CreateNavigator();

                // Build up an expression for the XPath the transform specified and hook up the namespace
                // resolver which will resolve namsepaces against the original XPath expression's XML context.
                XPathExpression transformExpression = navigator.Compile(
                    String.Format(CultureInfo.InvariantCulture, "boolean({0})", m_xpathExpression));

                // Get the namespaces into scope for use in the expression
                XmlNamespaceManager namespaceManager = new XmlNamespaceManager(m_inputNodes.NameTable);
                foreach (KeyValuePair<string, string> namespaceDeclaration in m_namespaces)
                {
                    namespaceManager.AddNamespace(namespaceDeclaration.Key, namespaceDeclaration.Value);
                }
                transformExpression.SetContext(namespaceManager);

                // Iterate over the input nodes, applying the XPath expression to each.  If the XPath
                // expression returns true for the node, then add it to the output NodeList
                XPathNodeIterator inputNodeIterator = navigator.Select("//. | //@*");
                while (inputNodeIterator.MoveNext())
                {
                    XPathNavigator current = inputNodeIterator.Current;
                    if ((bool)current.Evaluate(transformExpression))
                    {
                        outputNodes.Add((current as IHasXmlNode).GetNode());
                    }
                }
            }

            return outputNodes;
        }
    }
}
