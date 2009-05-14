// Copyright (c) Microsoft Corporation.  All rights reserved.

using System;
using System.Security.Cryptography;
using System.Security.Cryptography.Xml;
using System.Xml;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Security.Cryptography.Xml;

namespace Security.Cryptography.Xml.Test
{
    /// <summary>
    ///     Unit tests for the EncryptedXml class
    /// </summary>
    [TestClass]
    public class EncryptedXmlTests
    {
        private static string InputXml = @"<?xml version=""1.0"" encoding=""utf-8""?><root><child /></root>";

        [TestMethod]
        public void ReplaceData2DocumentElementTest()
        {
            XmlDocument doc = new XmlDocument();
            doc.PreserveWhitespace = true;
            doc.LoadXml(InputXml);

            using (Rijndael aes = new RijndaelManaged())
            {
                aes.GenerateKey();
                aes.GenerateIV();

                // Encrypt the XML document
                EncryptedXml encryptedXml = new EncryptedXml(doc);
                encryptedXml.AddKeyNameMapping("key", aes);

                EncryptedData encrypted = encryptedXml.Encrypt(doc.DocumentElement, "key");
                EncryptedXml.ReplaceElement(doc.DocumentElement, encrypted, false);

                // Decrypt it back
                XmlElement encryptedElement = doc.GetElementsByTagName("EncryptedData", EncryptedXml.XmlEncNamespaceUrl)[0] as XmlElement;

                EncryptedData encryptedData = new EncryptedData();
                encryptedData.LoadXml(encryptedElement);
                
                EncryptedXml decryptXml = new EncryptedXml(doc);
                decryptXml.AddKeyNameMapping("key", aes);

                byte[] decryptedData = decryptXml.DecryptData(encryptedData,
                                                              decryptXml.GetDecryptionKey(encryptedData, null));
                decryptXml.ReplaceData2(encryptedElement, decryptedData);
            }

            // Now that we've encrypted and decrypted the data, ensure that we have both the XML
            // declaration, and the root node in place.
            Assert.IsTrue(doc.FirstChild.NodeType == XmlNodeType.XmlDeclaration);
            Assert.AreEqual("root", doc.FirstChild.NextSibling.Name);
            Assert.AreEqual(InputXml, doc.OuterXml);
        }

        [TestMethod]
        public void ReplaceData2NonDocumentElementTest()
        {
            XmlDocument doc = new XmlDocument();
            doc.PreserveWhitespace = true;
            doc.LoadXml(InputXml);

            using (Rijndael aes = new RijndaelManaged())
            {
                aes.GenerateKey();
                aes.GenerateIV();

                // Encrypt the XML document
                EncryptedXml encryptedXml = new EncryptedXml(doc);
                encryptedXml.AddKeyNameMapping("key", aes);

                XmlElement secretElement = doc.GetElementsByTagName("child")[0] as XmlElement;
                EncryptedData encrypted = encryptedXml.Encrypt(secretElement, "key");
                EncryptedXml.ReplaceElement(secretElement, encrypted, false);

                // Decrypt it back
                XmlElement encryptedElement = doc.GetElementsByTagName("EncryptedData", EncryptedXml.XmlEncNamespaceUrl)[0] as XmlElement;

                EncryptedData encryptedData = new EncryptedData();
                encryptedData.LoadXml(encryptedElement);

                EncryptedXml decryptXml = new EncryptedXml(doc);
                decryptXml.AddKeyNameMapping("key", aes);

                byte[] decryptedData = decryptXml.DecryptData(encryptedData,
                                                              decryptXml.GetDecryptionKey(encryptedData, null));
                decryptXml.ReplaceData2(encryptedElement, decryptedData);
            }

            // Now that we've encrypted and decrypted the data, ensure that we have both the XML
            // declaration, and the root node in place.
            Assert.IsTrue(doc.FirstChild.NodeType == XmlNodeType.XmlDeclaration);
            Assert.AreEqual("root", doc.FirstChild.NextSibling.Name);
            Assert.AreEqual(InputXml, doc.OuterXml);
        }
    }
}
