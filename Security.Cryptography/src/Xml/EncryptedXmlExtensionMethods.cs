// Copyright (c) Microsoft Corporation.  All rights reserved.

using System;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography.Xml;
using System.Xml;

namespace Security.Cryptography.Xml
{
    /// <summary>
    ///     Extension methods for the EncryptedXml type
    /// </summary>
    public static class EncryptedXmlExtensionMethods
    {
        /// <summary>
        ///     Replace the XML element with the decrypted data.  This method works very much like the
        ///     standard ReplaceData API, with one exception.  If inputElement is the root element of an XML
        ///     document, ReplaceData2 will ensure that any other top-level XML items (such as the XML
        ///     declaration) will not be overwritten, whereas ReplaceData always overwrites the entire XML
        ///     document with the decrypted data.
        /// </summary>
        [SuppressMessage("Microsoft.Design", "CA1059:MembersShouldNotExposeCertainConcreteTypes", MessageId = "System.Xml.XmlNode", Justification = "This is to match the signature with the existing ReplaceData API")]
        public static void ReplaceData2(this EncryptedXml encryptedXml,
                                        XmlElement inputElement,
                                        byte[] decryptedData)
        {
            if (inputElement == null)
                throw new ArgumentNullException("inputElement");
            if (decryptedData == null)
                throw new ArgumentNullException("decryptedData");

            XmlNode parent = inputElement.ParentNode;
            if (parent.NodeType == XmlNodeType.Document)
            {
                // We're replacing the root element, so we need to
                //  1. Import the decrypted data into an XmlNode
                //  2. Get that node into the target document
                //  3. Replace the root element with the decrypted node
                
                XmlDocument importDocument = new XmlDocument();
                importDocument.LoadXml(encryptedXml.Encoding.GetString(decryptedData));

                XmlNode importedNode = inputElement.OwnerDocument.ImportNode(importDocument.DocumentElement, true);

                parent.RemoveChild(inputElement);
                parent.AppendChild(importedNode);
            }
            else
            {
                // We're not replacing the root, so the built-in ReplaceData API will work for this input
                // node.
                encryptedXml.ReplaceData(inputElement, decryptedData);
            }
        }
    }
}
