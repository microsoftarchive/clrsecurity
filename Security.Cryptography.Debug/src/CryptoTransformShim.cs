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
    internal sealed class ShimCryptoTransform : ICryptoTransform
    {
        private ICryptoTransform m_wrappedTransform;
        private Action m_lockCheck;

        internal ShimCryptoTransform(ICryptoTransform wrappedTransform, Action lockCheck)
        {
            if (wrappedTransform == null)
                throw new ArgumentNullException("wrappedTransform");

            m_wrappedTransform = wrappedTransform;
            m_lockCheck = lockCheck;
        }

        /// <summary>
        ///     Make sure that the transform is being used in a thread-safe manner
        /// </summary>
        private void CheckThreadAccess()
        {
            if (m_lockCheck != null)
            {
                m_lockCheck();
            }
        }

        //
        // Shim properties and methods
        //

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
            m_wrappedTransform.Dispose();
        }
    }
}
