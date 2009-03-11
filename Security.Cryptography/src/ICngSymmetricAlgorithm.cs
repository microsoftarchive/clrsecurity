// Copyright (c) Microsoft Corporation.  All rights reserved.

using System;
using System.Security.Cryptography;

namespace Security.Cryptography
{
    /// <summary>
    ///     Interface for symmetric algorithms implemented over the CNG layer of Windows to provide CNG
    ///     implementation details through.
    /// </summary>
    public interface ICngSymmetricAlgorithm : ICngAlgorithm
    {
        /// <summary>
        ///     Chaining mode to be used for the algorithm
        /// </summary>
        CngChainingMode CngMode { get; set; }
    }
}
