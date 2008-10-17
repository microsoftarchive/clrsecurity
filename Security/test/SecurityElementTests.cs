// Copyright (c) Microsoft Corporation.  All rights reserved.

using System;
using System.Security;
using System.Xml;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Security;

namespace Security.Test
{
    /// <summary>
    ///     Tests for the SecurityElement extension methods
    /// </summary>
    [TestClass]
    public sealed class SecurityElementTests
    {
        /// <summary>
        ///     Tests for conversion to XmlElement
        /// </summary>
        [TestMethod]
        public void ToXmlElementTest()
        {
            string originalXml =
                @"<rootElement>
                     <firstChild firstAttribute=""true"" secondAttribute=""0"" />
                     <secondChild>
                        InnerText
                     </secondChild>
                     <thirdChild />
                  </rootElement>";

            SecurityElement securityElement = SecurityElement.FromString(originalXml);
            XmlElement converted = securityElement.ToXmlElement();

            Assert.AreEqual("rootElement", converted.Name);
            Assert.AreEqual(0, converted.Attributes.Count);
            Assert.AreEqual(3, converted.ChildNodes.Count);

            XmlElement firstChild = converted.ChildNodes[0] as XmlElement;
            Assert.AreEqual("firstChild", firstChild.Name);
            Assert.AreEqual(2, firstChild.Attributes.Count);
            Assert.AreEqual("true", firstChild.Attributes["firstAttribute"].Value);
            Assert.AreEqual("0", firstChild.Attributes["secondAttribute"].Value);
            Assert.AreEqual(0, firstChild.ChildNodes.Count);
            Assert.IsTrue(String.IsNullOrEmpty(firstChild.InnerText));

            XmlElement secondChild = converted.ChildNodes[1] as XmlElement;
            Assert.AreEqual("secondChild", secondChild.Name);
            Assert.AreEqual(0, secondChild.Attributes.Count);
            Assert.AreEqual(1, secondChild.ChildNodes.Count);
            Assert.AreEqual("InnerText", secondChild.InnerText.Trim());

            XmlElement thirdChild = converted.ChildNodes[2] as XmlElement;
            Assert.AreEqual("thirdChild", thirdChild.Name);
            Assert.AreEqual(0, thirdChild.Attributes.Count);
            Assert.AreEqual(0, thirdChild.ChildNodes.Count);
            Assert.IsTrue(String.IsNullOrEmpty(thirdChild.InnerText));
        }

        /// <summary>
        ///     Tests for XML comparison
        /// </summary>
        [TestMethod]
        public void XmlEqualsTest()
        {
            string xml = @"<root><child1/><child2><child3 attr1=""a"" /></child2><child4>Text</child4></root>";

             SecurityElement original = SecurityElement.FromString(xml);

            // Elements should be equal to themseleves, and to elements made from the same XML
            SecurityElement same = SecurityElement.FromString(xml);
            Assert.IsTrue(original.XmlEquals(original));
            Assert.IsTrue(original.XmlEquals(same));
            Assert.IsTrue(same.XmlEquals(original));

            // Adding attributes should cause a comparison error
            SecurityElement addAttr = SecurityElement.FromString(xml);
            addAttr.AddAttribute("newAttr", "value");
            Assert.IsFalse(original.XmlEquals(addAttr));
            Assert.IsFalse(addAttr.XmlEquals(original));

            // Adding children should cause comparison errors
            SecurityElement addChild = SecurityElement.FromString(xml);
            addChild.AddChild(new SecurityElement("newChild"));
            Assert.IsFalse(original.XmlEquals(addChild));
            Assert.IsFalse(addChild.XmlEquals(original));
        }
    }
}
