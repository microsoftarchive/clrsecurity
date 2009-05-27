// Copyright (c) Microsoft Corporation.  All rights reserved.

using System;
using System.Collections;
using System.Diagnostics.CodeAnalysis;
using System.Security;
using System.Xml;

namespace Security
{
    /// <summary>
    ///     SecurityElementExtensionMehods provides several extension methods for the <see
    ///     cref="SecurityElement" /> class. This type is in the Security namespace (not the System.Security
    ///     namespace), so in order to use these extension methods, you will need to make sure you include
    ///     this namespace as well as a reference to Security.dll.
    /// </summary>
    public static class SecurityElementExtensionMethods
    {
        /// <summary>
        ///     Convert a SecurityElement XML tree to an equivilent tree in the System.Xml object model
        /// </summary>
        [SuppressMessage("Microsoft.Design", "CA1059:MembersShouldNotExposeCertainConcreteTypes", MessageId = "System.Xml.XmlNode", Justification = "This is an explicit conversion function to XmlElements")]
        public static XmlElement ToXmlElement(this SecurityElement securityElement)
        {
            return ToXmlElement(securityElement, new XmlDocument());
        }

        /// <summary>
        ///     Convert a SecurityElement XML tree to an equivilent tree in the System.Xml object model
        /// </summary>
        /// <param name="securityElement">security element to convert</param>
        /// <param name="containingDocument">XML document to create the XML tree from</param>
        /// <exception cref="ArgumentNullException">if <paramref name="containingDocument" /> is null</exception>
        [SuppressMessage("Microsoft.Design", "CA1059:MembersShouldNotExposeCertainConcreteTypes", MessageId = "System.Xml.XmlNode", Justification = "This is an explicit conversion function to XmlElements")]
        [SuppressMessage("Microsoft.Design", "CA1059:MembersShouldNotExposeCertainConcreteTypes", MessageId = "System.Xml.XmlNode", Justification = "XmlDocument is needed as a factory for building up the XmlElement tree")]
        public static XmlElement ToXmlElement(this SecurityElement securityElement,
                                              XmlDocument containingDocument)
        {
            if (containingDocument == null)
                throw new ArgumentNullException("containingDocument");

            XmlElement xmlElement = containingDocument.CreateElement(securityElement.Tag);

            // Copy over any attributes
            if (securityElement.Attributes != null)
            {
                foreach (string attributeName in securityElement.Attributes.Keys)
                {
                    XmlAttribute xmlAttribute = containingDocument.CreateAttribute(attributeName);
                    xmlAttribute.Value = securityElement.Attributes[attributeName] as string;
                    xmlElement.Attributes.Append(xmlAttribute);
                }
            }

            // Recursively copy child nodes
            if (securityElement.Children != null)
            {
                foreach (SecurityElement childElement in securityElement.Children)
                {
                    xmlElement.AppendChild(childElement.ToXmlElement(containingDocument));
                }
            }

            // If we have inner text, copy that as wel
            if (!String.IsNullOrEmpty(securityElement.Text))
            {
                xmlElement.AppendChild(containingDocument.CreateTextNode(securityElement.Text));
            }

            return xmlElement;
        }

        /// <summary>
        ///     Perform a case-senstive comparsion of the content of two security elements
        /// </summary>
        /// <param name="lhs">SecurityElement to compare</param>
        /// <param name="rhs">SecurityElement to compare against</param>
        /// <exception cref="ArgumentNullException">if <paramref name="rhs"/> is null</exception>
        public static bool XmlEquals(this SecurityElement lhs, SecurityElement rhs)
        {
            return lhs.XmlEquals(rhs, StringComparison.Ordinal);
        }

        /// <summary>
        ///     Perform a comparison of the content of two security elements
        /// </summary>
        /// <param name="lhs">SecurityElement to compare</param>
        /// <param name="rhs">SecurityElement to compare against</param>
        /// <param name="comparisonType">type of comparison to perform</param>
        /// <exception cref="ArgumentNullException">if <paramref name="rhs"/> is null</exception>
        public static bool XmlEquals(this SecurityElement lhs,
                                     SecurityElement rhs,
                                     StringComparison comparisonType)
        {
            if (rhs == null)
                throw new ArgumentNullException("rhs");

            // Make sure the tags of the elements match
            if (!String.Equals(lhs.Tag, rhs.Tag, comparisonType))
            {
                return false;
            }

            // Check any contained text
            if (!String.Equals(lhs.Text, rhs.Text, comparisonType))
            {
                return false;
            }

            // Both elements need to have the same number of attributes, and each attribute found in the first
            // element must also be found in the second element - with the same value
            if (lhs.Attributes != null)
            {
                if (rhs.Attributes == null)
                {
                    return false;
                }

                if (lhs.Attributes.Count != rhs.Attributes.Count)
                {
                    return false;
                }

                foreach (DictionaryEntry attribute in lhs.Attributes)
                {
                    if (!rhs.Attributes.ContainsKey(attribute.Key))
                    {
                        return false;
                    }

                    if (!String.Equals(attribute.Value as string,
                                       rhs.Attributes[attribute.Key] as string,
                                       comparisonType))
                    {
                        return false;
                    }
                }
            }
            else if (rhs.Attributes != null)
            {
                return false;
            }

            // Finally, each side needs to have the same number of children, and each child element of the
            // first must match the corresponding child element in the second
            if (lhs.Children != null)
            {
                if (rhs.Children == null)
                {
                    return false;
                }

                if (lhs.Children.Count != rhs.Children.Count)
                {
                    return false;
                }

                for (int i = 0; i < lhs.Children.Count; ++i)
                {
                    SecurityElement lhsChild = lhs.Children[i] as SecurityElement;
                    SecurityElement rhsChild = rhs.Children[i] as SecurityElement;

                    if (!lhsChild.XmlEquals(rhsChild, comparisonType))
                    {
                        return false;
                    }
                }
            }
            else if (rhs.Children != null)
            {
                return false;
            }

            // If all of the above checks match, we'll declare the two security elements to be equal
            return true;
        }
    }
}
