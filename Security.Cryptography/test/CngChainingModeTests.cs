// Copyright (c) Microsoft Corporation.  All rights reserved.

using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Security.Cryptography;

namespace Security.Cryptography.Test
{
    /// <summary>
    ///     Unit tests for the CngChainingMode class
    /// </summary>
    [TestClass]
    public class CngChainingModeTests
    {
        /// <summary>
        ///     Tests for creating and comparing custom CNG chaining modes
        /// </summary>
        [TestMethod]
        public void CngChainingModeCustomTest()
        {
            CngChainingMode mode1 = new CngChainingMode("Custom chaining mode 1");
            CngChainingMode mode2 = new CngChainingMode("Custom chaining mode 2");
            CngChainingMode secondMode1 = new CngChainingMode("Custom chaining mode 1");

            Assert.AreEqual("Custom chaining mode 1", mode1.ChainingMode);
            Assert.AreEqual("Custom chaining mode 2", mode2.ChainingMode);

            Assert.IsFalse(mode1 == mode2);
            Assert.IsFalse(mode2 == mode1);
            Assert.IsFalse(mode2 == secondMode1);
            Assert.IsFalse(secondMode1 == mode2);
            Assert.IsTrue(mode1 == secondMode1);
            Assert.IsTrue(secondMode1 == mode1);

            Assert.IsFalse(mode1.Equals(mode2));
            Assert.IsFalse(mode2.Equals(mode1));
            Assert.IsFalse(mode2.Equals(secondMode1));
            Assert.IsFalse(secondMode1.Equals(mode2));
            Assert.IsTrue(mode1.Equals(secondMode1));
            Assert.IsTrue(secondMode1.Equals(mode1));

            Assert.IsTrue(mode1 != mode2);
            Assert.IsTrue(mode2 != mode1);
            Assert.IsTrue(mode2 != secondMode1);
            Assert.IsTrue(secondMode1 != mode2);
            Assert.IsFalse(mode1 != secondMode1);
            Assert.IsFalse(secondMode1 != mode1);

            Assert.IsFalse(mode1 == null);
            Assert.IsTrue(mode1 != null);
            Assert.IsFalse(mode1.Equals(null));
        }

        /// <summary>
        ///     Tests to validate the built in chaining modes have the correct values
        /// </summary>
        [TestMethod]
        public void CngChainingModeBuiltInTest()
        {
            Assert.AreEqual("ChainingModeCBC", CngChainingMode.Cbc.ChainingMode);
            Assert.AreEqual("ChainingModeCCM", CngChainingMode.Ccm.ChainingMode);
            Assert.AreEqual("ChainingModeCFB", CngChainingMode.Cfb.ChainingMode);
            Assert.AreEqual("ChainingModeECB", CngChainingMode.Ecb.ChainingMode);
            Assert.AreEqual("ChainingModeGCM", CngChainingMode.Gcm.ChainingMode);
        }

        /// <summary>
        ///     Test to ensure we throw an ArgumentNullException for null chaining modes
        /// </summary>
        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void CngChainingModeCreateNullTest()
        {
            new CngChainingMode(null);
        }

        /// <summary>
        ///     Test to ensure we throw an ArgumentException for empty chaining modes
        /// </summary>
        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void CngChainingModeCreateEmptyTest()
        {
            new CngChainingMode(String.Empty);
        }
    }
}
