// Copyright (c) Microsoft Corporation.  All rights reserved.

using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.Xml;
using System.Xml;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Security.Cryptography.Xml;

namespace Security.Cryptography.Xml.Test
{
    /// <summary>
    ///     Unit tests for the XmlDsigXPathWithNamespacesTransform class
    /// </summary>
    [TestClass]
    public class XmlDsigXPathWithNamespacesTransformTests
    {
        private const string RawXml =
@"<xml xmlns:clrsec='http://www.codeplex.com/clrsecurity'>
  <signedNode sign='true'/>
  <unsignedNode>
    <clrsec:signedNamespaceNode clrsec:sign='true'/>
  </unsignedNode>
</xml>";

        /// <summary>
        ///     Ensure that we can sign XML with the XmlDsigXPathWithNamespacesTransform and verify the
        ///     produced XML with the standard XPath transform
        /// </summary>
        [TestMethod]
        public void XmlDsigXPathWithNamespacesTransformNoNamespaceRoundTripTest()
        {
            RSACryptoServiceProvider key = new RSACryptoServiceProvider();

            XmlDocument doc = new XmlDocument();
            doc.PreserveWhitespace = true;
            doc.LoadXml(RawXml);

            SignedXml signer = new SignedXml(doc);

            Reference reference = new Reference("");
            reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
            reference.AddTransform(new XmlDsigXPathWithNamespacesTransform("ancestor-or-self::node()[@sign='true']"));
            signer.AddReference(reference);

            signer.SigningKey = key;
            signer.ComputeSignature();

            XmlElement signature = signer.GetXml();
            doc.DocumentElement.AppendChild(signature);

            // Now try to verify - this will use the built in XPath transform to do the verification, since
            // we have to modify machine.config to use custom transforms.
            SignedXml verifier = new SignedXml(doc);
            verifier.LoadXml(doc.GetElementsByTagName("Signature")[0] as XmlElement);

            Assert.IsTrue(verifier.CheckSignature(key));

            // We should also be able to verify the signature after modifying the unsignedNode node,
            // since the XPath should have excluded it.
            XmlElement unsigned = doc.GetElementsByTagName("unsignedNode")[0] as XmlElement;
            XmlAttribute unsignedAttr = doc.CreateAttribute("state");
            unsignedAttr.Value = "unsigned";
            unsigned.Attributes.Append(unsignedAttr);

            verifier = new SignedXml(doc);
            verifier.LoadXml(doc.GetElementsByTagName("Signature")[0] as XmlElement);
            Assert.IsTrue(verifier.CheckSignature(key));

            // However, we should not be able to modify the signedNode node
            XmlElement signed = doc.GetElementsByTagName("signedNode")[0] as XmlElement;
            XmlAttribute signedAttr = doc.CreateAttribute("state");
            signedAttr.Value = "signed";
            signed.Attributes.Append(signedAttr);

            verifier = new SignedXml(doc);
            verifier.LoadXml(doc.GetElementsByTagName("Signature")[0] as XmlElement);
            Assert.IsFalse(verifier.CheckSignature(key));
        }

        /// <summary>
        ///     Ensure that we can sign XML with the XmlDsigXPathWithNamespacesXPathTransform and verify the
        ///     produced XML with the standard XPath transform if we use namespaces we explicitly bring into
        ///     scope.
        /// </summary>
        [TestMethod]
        public void XmlDsigXPathWithNamespacesTransformExplicitNamespaceRoundTripTest()
        {
            RSACryptoServiceProvider key = new RSACryptoServiceProvider();

            XmlDocument doc = new XmlDocument();
            doc.PreserveWhitespace = true;
            doc.LoadXml(RawXml);

            SignedXml signer = new SignedXml(doc);

            Reference reference = new Reference("");
            reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());

            Dictionary<string, string> explicitNamespaces = new Dictionary<string, string>();
            explicitNamespaces["clrsec"] = "http://www.codeplex.com/clrsecurity";
            reference.AddTransform(new XmlDsigXPathWithNamespacesTransform("ancestor-or-self::node()[@clrsec:sign='true']", explicitNamespaces));

            signer.AddReference(reference);

            signer.SigningKey = key;
            signer.ComputeSignature();

            XmlElement signature = signer.GetXml();
            doc.DocumentElement.AppendChild(signature);

            // Now try to verify - this will use the built in XPath transform to do the verification, since
            // we have to modify machine.config to use custom transforms.
            SignedXml verifier = new SignedXml(doc);
            verifier.LoadXml(doc.GetElementsByTagName("Signature")[0] as XmlElement);

            Assert.IsTrue(verifier.CheckSignature(key));

            // We should also be able to verify the signature after modifying the unsignedNode node,
            // since the XPath should have excluded it.
            XmlElement unsigned = doc.GetElementsByTagName("unsignedNode")[0] as XmlElement;
            XmlAttribute unsignedAttr = doc.CreateAttribute("state");
            unsignedAttr.Value = "unsigned";
            unsigned.Attributes.Append(unsignedAttr);

            verifier = new SignedXml(doc);
            verifier.LoadXml(doc.GetElementsByTagName("Signature")[0] as XmlElement);
            Assert.IsTrue(verifier.CheckSignature(key));

            // Modifying the signedNode should also be allowed, since it is not using a clrsec:sign attribute
            XmlElement signed = doc.GetElementsByTagName("signedNode")[0] as XmlElement;
            XmlAttribute unsignedAttr2 = doc.CreateAttribute("state");
            unsignedAttr2.Value = "unsigned";
            unsigned.Attributes.Append(unsignedAttr2);

            verifier = new SignedXml(doc);
            verifier.LoadXml(doc.GetElementsByTagName("Signature")[0] as XmlElement);
            Assert.IsTrue(verifier.CheckSignature(key));

            // However, we should not be able to modify the signedNode node
            XmlElement signedNamespace = doc.GetElementsByTagName("signedNamespaceNode", "http://www.codeplex.com/clrsecurity")[0] as XmlElement;
            XmlAttribute signedAttr = doc.CreateAttribute("state");
            signedAttr.Value = "signed";
            signedNamespace.Attributes.Append(signedAttr);

            verifier = new SignedXml(doc);
            verifier.LoadXml(doc.GetElementsByTagName("Signature")[0] as XmlElement);
            Assert.IsFalse(verifier.CheckSignature(key));
        }

        /// <summary>
        ///     Ensure that we can sign using namespaces in the XPath expression which are not present in
        ///     the XPath node itself
        /// </summary>
        [TestMethod]
        public void XmlDsigXPathWithNamespacesTransformSignWithNamespacesTest()
        {
            RSACryptoServiceProvider key = new RSACryptoServiceProvider();

            XmlDocument doc = new XmlDocument();
            doc.PreserveWhitespace = true;
            doc.LoadXml(RawXml);

            SignedXml signer = new SignedXml(doc);

            Reference reference = new Reference("");
            reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());

            Dictionary<string, string> additionalNamespaces = new Dictionary<string, string>();
            additionalNamespaces["clrsec"] = "http://www.codeplex.com/clrsecurity";
            reference.AddTransform(new XmlDsigXPathWithNamespacesTransform("ancestor-or-self::node()[@clrsec:sign='true']", null, additionalNamespaces));

            signer.AddReference(reference);

            signer.SigningKey = key;
            signer.ComputeSignature();

            // We just want to ensure we got here without an exception -- we can't verify the signature
            // directly because without modifying machine.config SignedXml will use the standard XPath
            // transform to process the signature and it will be unable to handle the namespaces.
            Assert.IsTrue(true);
        }

        /// <summary>
        ///     Ensure that an ArgumentNullException is thrown for a null XPath query
        /// </summary>
        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void XmlDsigXPathWithNamespacesTransformConstructNullXPathTest()
        {
            new XmlDsigXPathWithNamespacesTransform(null);
        }
    }
}
