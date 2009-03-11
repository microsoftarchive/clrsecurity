// Copyright (c) Microsoft Corporation.  All rights reserved.

using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography.Xml;
using System.Xml;

namespace Security.Cryptography.Xml
{
    /// <summary>
    ///     Class to produce XML digital signature transform objects more easily than the
    ///     System.Security.dll object model exposes.
    /// </summary>
    public static class TransformFactory
    {
        /// <summary>
        ///     Create an XPath transform for the specified query string.  This overload does not add any
        ///     namespace declarations for use within the XPath query.
        /// </summary>
        [SuppressMessage("Microsoft.Naming", "CA1702:CompoundWordsShouldBeCasedCorrectly", MessageId = "XPath", Justification = "This matches the XPath spelling in the rest of the framework.")]
        public static XmlDsigXPathTransform CreateXPathTransform(string xpath)
        {
            return CreateXPathTransform(xpath, null);
        }

        /// <summary>
        ///     Create an XPath transform for a specific query string.  This overload also allows namespace
        ///     mappings for XML namespaces used in the XPath query.
        /// </summary>
        [SuppressMessage("Microsoft.Naming", "CA1702:CompoundWordsShouldBeCasedCorrectly", MessageId = "XPath", Justification = "This matches the XPath spelling in the rest of the framework.")]
        public static XmlDsigXPathTransform CreateXPathTransform(string xpath, IDictionary<string, string> namespaces)
        {
            if (xpath == null)
                throw new ArgumentNullException("xpath");

            // XmlDsigXPath transform only sets its XPath query when it loads itself from XML.  In order to
            // setup the transform, we'll build up XML representing the transform, and then load that XML
            // into the transform.
            XmlDocument doc = new XmlDocument();
            XmlElement xpathElement = doc.CreateElement("XPath");

            // The XPath query is the text value of the XPath node of the transform.
            xpathElement.InnerText = xpath;

            // Add the namespaces that should be in scope for the XPath expression.
            if (namespaces != null)
            {
                foreach (string namespaceAlais in namespaces.Keys)
                {
                    // Namespaces in scope for the XPath query must be declared on the XPath element.  For
                    // each namespace mapping, generate a namespace declaration attribute to apply to the
                    // XPath element.
                    XmlAttribute namespaceDeclaration = doc.CreateAttribute("xmlns",
                                                                            namespaceAlais,
                                                                            "http://www.w3.org/2000/xmlns/");
                    namespaceDeclaration.Value = namespaces[namespaceAlais];
                    xpathElement.Attributes.Append(namespaceDeclaration);
                }
            }

            // Build a transform from the XML representation
            XmlDsigXPathTransform xpathTransform = new XmlDsigXPathTransform();
            xpathTransform.LoadInnerXml(xpathElement.SelectNodes("."));

            return xpathTransform;
        }
    }
}
