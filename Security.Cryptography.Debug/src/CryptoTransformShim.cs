// Copyright (c) Microsoft Corporation.  All rights reserved.

using System;
using System.Diagnostics;
using System.Security.Cryptography;

namespace Security.Cryptography
{
    /// <summary>
    ///     Shim crypto transform which hooks acess to a wrapped transform and ensures it is being used properly.
    ///     
    ///     See code:System.Security.Cryptography.SymmetricAlgorithmShim
    /// </summary>
    internal class CryptoTransformShim : ICryptoTransform
#if !FXONLY_BUILD
        , ICryptoTransform2
#endif // !FXONLY_BUILD
    {
        private ICryptoTransform m_wrappedTransform;
        private Action m_lockCheck;

        internal CryptoTransformShim(ICryptoTransform wrappedTransform, Action lockCheck)
        {
            if (wrappedTransform == null)
                throw new ArgumentNullException("wrappedTransform");

            m_wrappedTransform = wrappedTransform;
            m_lockCheck = lockCheck;
        }

        /// <summary>
        ///     Make sure that the transform is being used in a thread-safe manner
        /// </summary>
        protected void CheckThreadAccess()
        {
            if (m_lockCheck != null)
            {
                m_lockCheck();
            }
        }

#if !FXONLY_BUILD
        /// <summary>
        ///     Provide access to the wrapped transform for derived shims
        /// </summary>
        protected ICryptoTransform WrappedTransform
        {
            get { return m_wrappedTransform; }
        }
#endif // !FXONLY_BUILD

        //
        // Shim properties and methods
        //

#if !FXONLY_BUILD
        public bool CanChainBlocks
        {
            get
            {
                ICryptoTransform2 wrappedTransform2 = m_wrappedTransform as ICryptoTransform2;

                if (wrappedTransform2 != null)
                {
                    return wrappedTransform2.CanChainBlocks;
                }
                else
                {
                    // Transforms that don't implement ICryptoTransform2 are assumed to be able to chain
                    // multiple blocks since ICryptoTransform does not provide a way to express that this is
                    // not possible.
                    return true;
                }
            }
        }
#endif // !FXONLY_BUILD

        public bool CanReuseTransform
        {
            get { CheckThreadAccess(); return m_wrappedTransform.CanReuseTransform; }
        }

        public bool CanTransformMultipleBlocks
        {
            get { CheckThreadAccess(); return m_wrappedTransform.CanTransformMultipleBlocks; }
        }

        public int InputBlockSize
        {
            get { CheckThreadAccess(); return m_wrappedTransform.InputBlockSize; }
        }

        public int OutputBlockSize
        {
            get { CheckThreadAccess(); return m_wrappedTransform.OutputBlockSize; }
        }

        public int TransformBlock(byte[] inputBuffer,
                                  int inputOffset,
                                  int inputCount,
                                  byte[] outputBuffer,
                                  int outputOffset)
        {
            CheckThreadAccess();
            return m_wrappedTransform.TransformBlock(inputBuffer,
                                                     inputOffset,
                                                     inputCount,
                                                     outputBuffer,
                                                     outputOffset);
        }

        public byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
        {
            CheckThreadAccess();
            return m_wrappedTransform.TransformFinalBlock(inputBuffer, inputOffset, inputCount);
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (disposing)
            {
                m_wrappedTransform.Dispose();
            }
        }
    }
}
