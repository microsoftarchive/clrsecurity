// Copyright (c) Microsoft Corporation.  All rights reserved.

using System;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.Serialization;
using System.Security.Cryptography;

namespace Security.Cryptography
{
    /// <summary>
    ///     Exception thrown when a diagnostic check on a symmetric encryption or decryption operation fails
    ///     
    ///     See code:System.Security.Cryptography.SymmetricAlgorithmLogger#SymmetricAlgorithmDiagnostics
    /// </summary>
    [Serializable]
    [SuppressMessage("Microsoft.Design", "CA1032:ImplementStandardExceptionConstructors", Justification = "CryptographicDiagnosticException is not intended to be thrown by consumers of this library.")]
    public sealed class CryptographicDiagnosticException : CryptographicException
    {
        [SuppressMessage("Microsoft.Design", "CA1032:ImplementStandardExceptionConstructors", Justification = "CryptographicDiagnosticException is not intended to be thrown by consumers of this library.")]
        internal CryptographicDiagnosticException(string message) : base(message)
        {
        }

        private CryptographicDiagnosticException(SerializationInfo info, StreamingContext context) : base(info, context)
        {
        }
    }
}
