// Copyright (c) Microsoft Corporation.  All rights reserved.

using System;
using System.Diagnostics;
using System.Security.Cryptography;

namespace Security.Cryptography
{
#if !FXONLY_BUILD
    /// <summary>
    ///     Shim authenticated crypto transform which hooks acess to a wrapped transform and ensures it is
    ///     being used properly.
    ///     
    ///     See code:System.Security.Cryptography.AuthenticatedSymmetricAlgorithmShim
    /// </summary>
    internal sealed class AuthenticatedCryptoTransformShim : CryptoTransformShim, IAuthenticatedCryptoTransform
    {
        internal AuthenticatedCryptoTransformShim(IAuthenticatedCryptoTransform wrappedTransform,
                                                  Action lockCheck)
            : base(wrappedTransform, lockCheck)
        {
        }

        /// <summary>
        ///     Provide access to the wrapped transform typed as an authenticated wrapped transform
        /// </summary>
        private IAuthenticatedCryptoTransform WrappedAuthenticatedTransform
        {
            get
            {
                IAuthenticatedCryptoTransform authenticatedTransform = WrappedTransform as IAuthenticatedCryptoTransform;
                Debug.Assert(authenticatedTransform != null, "authenticatedTransform != null");
                return authenticatedTransform;
            }
        }

        //
        // Shim properties and methods
        // 

        public byte[] GetTag()
        {
            CheckThreadAccess();
            return WrappedAuthenticatedTransform.GetTag();
        }
    }
#endif // !FXONLY_BUILD
}
