// Copyright (c) Microsoft Corporation.  All rights reserved.

using System;
using System.Collections.Generic;
using System.Security.Cryptography.Xml;
using System.Xml;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Security.Cryptography.Xml;

namespace Security.Cryptography.Xml.Test
{
    /// <summary>
    ///     Unit tests for the TransformFactory class
    /// </summary>
    [TestClass]
    public class TransformFactoryTests
    {
        /// <summary>
        ///     Ensure that we can create correct XPath transforms
        /// </summary>
        [TestMethod]
        public void TransformFactoryCreateXPathTest()
        {
            string xpathQuery = "ancestor-or-self::*[@_Id='signme']";

            XmlDsigXPathTransform transform = TransformFactory.CreateXPathTransform(xpathQuery);
            Assert.IsNotNull(transform);

            // XmlDSigXPathTransform doesn't directly expose its state, so we validate that the transform is
            // setup correctly via its output XML.
            XmlElement transformXml = transform.GetXml();

            XmlNodeList xpathElements = transformXml.GetElementsByTagName("XPath");
            Assert.AreEqual(1, xpathElements.Count);

            XmlElement xpathXml = xpathElements[0] as XmlElement;
            Assert.AreEqual(xpathQuery, xpathXml.InnerText);
        }

        /// <summary>
        ///     Ensure that we can create correct XPath transforms with namespaces in scope
        /// </summary>
        [TestMethod]
        public void TransformFactoryCreateXPathNamespaceTest()
        {
            string testNamespace1Uri = "http://www.codeplex.com/clrsecurity/testnamespace1";
            string testNamespace2Uri = "http://www.codeplex.com/clrsecurity/testnamespace2";
            string xpathQuery = "ancestor-or-self::*[@_Id='testns1:signme']";

            var namespaces = new Dictionary<string, string>();
            namespaces["testns1"] = testNamespace1Uri;
            namespaces["testns2"] = testNamespace2Uri;

            XmlDsigXPathTransform transform = TransformFactory.CreateXPathTransform(xpathQuery, namespaces);
            Assert.IsNotNull(transform);

            // XmlDSigXPathTransform doesn't directly expose its state, so we validate that the transform is
            // setup correctly via its output XML.
            XmlElement transformXml = transform.GetXml();

            XmlNodeList xpathElements = transformXml.GetElementsByTagName("XPath");
            Assert.AreEqual(1, xpathElements.Count);

            XmlElement xpathXml = xpathElements[0] as XmlElement;
            Assert.AreEqual(xpathQuery, xpathXml.InnerText);

            Assert.AreEqual(testNamespace1Uri, xpathXml.GetNamespaceOfPrefix("testns1"));
            Assert.AreEqual(testNamespace2Uri, xpathXml.GetNamespaceOfPrefix("testns2"));
        }

        /// <summary>
        ///     Ensure that an ArgumentNullException is thrown for a null XPath query
        /// </summary>
        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void TransformFactoryCreateNullXPathTest()
        {
            TransformFactory.CreateXPathTransform(null);
        }
    }
}
