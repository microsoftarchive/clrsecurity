// Copyright (c) Microsoft Corporation.  All rights reserved.

using System;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;

namespace Security.Cryptography
{
    /// <summary>
    ///     HMAC-SHA256 implementation on top of CNG
    /// </summary>
    [SuppressMessage("Microsoft.Naming", "CA1709:IdentifiersShouldBeCasedCorrectly", MessageId = "HMACSHA", Justification = "This matches the HMAC naming in the BCL")]
    public sealed class HMACSHA256Cng : HMAC
    {
        private const int BlockSize = 64;

        private BCryptHMAC m_hmac;

        public HMACSHA256Cng() : this(RNGCng.GenerateKey(BlockSize))
        {
        }

        public HMACSHA256Cng(byte[] key) : this(key, CngProvider2.MicrosoftPrimitiveAlgorithmProvider)
        {
        }

        public HMACSHA256Cng(byte[] key, CngProvider provider)
        {
            if (key == null)
                throw new ArgumentNullException("key");
            if (provider == null)
                throw new ArgumentNullException("provider");

            HashName = "SHA256";

            m_hmac = new BCryptHMAC(CngAlgorithm.Sha256, provider, HashName, BlockSize, key);
        }

        protected override void Dispose(bool disposing)
        {
            try
            {
                if (disposing)
                {
                    if (m_hmac != null)
                    {
                        (m_hmac as IDisposable).Dispose();
                    }
                }
            }
            finally
            {
                base.Dispose(disposing);
            }
        }

        //
        // Forwarded APIs
        //

        public override bool CanReuseTransform
        {
            get { return m_hmac.CanReuseTransform; }
        }

        public override bool CanTransformMultipleBlocks
        {
            get { return m_hmac.CanTransformMultipleBlocks; }
        }

        public override byte[] Hash
        {
            get { return m_hmac.Hash; }
        }

        public override int HashSize
        {
            get { return m_hmac.HashSize; }
        }

        public override int InputBlockSize
        {
            get { return m_hmac.InputBlockSize; }
        }

        public override byte[] Key
        {
            get { return m_hmac.Key; }
            set { m_hmac.Key = value; }
        }

        public override int OutputBlockSize
        {
            get { return m_hmac.OutputBlockSize; }
        }

        protected override void HashCore(byte[] rgb, int ib, int cb)
        {
            m_hmac.HashCoreImpl(rgb, ib, cb);
        }

        protected override byte[] HashFinal()
        {
            return m_hmac.HashFinalImpl();
        }

        public override void Initialize()
        {
            m_hmac.Initialize();
        }
    }
}
