// Copyright (c) Microsoft Corporation.  All rights reserved.

using System;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;

namespace Security.Cryptography
{
#if !FXONLY_BUILD
    /// <summary>
    ///     Extension methods for the AuthenticatedSymmetricAlgorithm class which enable setting up logging
    ///     and verification.  SymmetricAlgorithm's extension methods already know how to setup diagnostics
    ///     for an authenticated symmetric algortihm, so these extension methods exist just to type the
    ///     return value more strongly.
    ///
    ///     See code:System.Security.Cryptography.SymmetricAlgorithmExtensionMethods
    /// </summary>
    public static class AuthenticatedSymmetricAlgorithmExtensionMethods
    {
        /// <summary>
        ///     Create an AuthenticatedSymmetricAlgorithm which logs the encryption operation of the input
        ///     algorithm, but does not monitor for thread safe access to the object.
        /// </summary>
        public static AuthenticatedSymmetricAlgorithm EnableLogging(this AuthenticatedSymmetricAlgorithm loggedAlgorithm)
        {
            return loggedAlgorithm.EnableLogging(new SymmetricAlgorithmDiagnosticOptions() { CheckThreadSafety = false });
        }

        /// <summary>
        ///     Create an AuhtenticatedSymmetricAlgorithm which logs the encryption operation of the input algorithm
        /// </summary>
        [SuppressMessage("Microsoft.Design", "CA1011:ConsiderPassingBaseTypesAsParameters", Justification = "Ensures a compile time error if you're trying to log an unauthenticated symmetric algorithm as an authenticated one.")]
        public static AuthenticatedSymmetricAlgorithm EnableLogging(this AuthenticatedSymmetricAlgorithm loggedAlgorithm,
                                                                    SymmetricAlgorithmDiagnosticOptions options)
        {
            AuthenticatedSymmetricAlgorithm wrappedAlgorithm =
                (loggedAlgorithm as SymmetricAlgorithm).EnableLogging(options) as AuthenticatedSymmetricAlgorithm;

            Debug.Assert(wrappedAlgorithm != null, "Logged authenticated algorithm did not wrap into an authenticated algortihm");
            return wrappedAlgorithm;
        }

        /// <summary>
        ///     Create an AuthenticatedSymmetricAlgorithm which verifies the decryption operations done on it
        ///     have state which matches captured encryption state. This overload does not monitor for thread
        ///     safe access to the object.
        /// </summary>
        public static AuthenticatedSymmetricAlgorithm EnableDecryptionVerification(this AuthenticatedSymmetricAlgorithm loggedAlgorithm,
                                                                                   AuthenticatedSymmetricEncryptionState encryptionState)
        {
            return loggedAlgorithm.EnableDecryptionVerification(encryptionState,
                                                                new SymmetricAlgorithmDiagnosticOptions() { CheckThreadSafety = false });
        }

        /// <summary>
        ///     Create an AuthenticatedSymmetricAlgorithm which verifies the decryption operations done on it
        ///     have state which matches captured encryption state.
        /// </summary>
        [SuppressMessage("Microsoft.Design", "CA1011:ConsiderPassingBaseTypesAsParameters", Justification = "Ensures a compile time error if you're trying to log an unauthenticated symmetric algorithm as an authenticated one.")]
        public static AuthenticatedSymmetricAlgorithm EnableDecryptionVerification(this AuthenticatedSymmetricAlgorithm loggedAlgorithm,
                                                                                   AuthenticatedSymmetricEncryptionState encryptionState,
                                                                                   SymmetricAlgorithmDiagnosticOptions options)
        {
            AuthenticatedSymmetricAlgorithm wrappedAlgorithm =
                (loggedAlgorithm as SymmetricAlgorithm).EnableDecryptionVerification(encryptionState, options) as AuthenticatedSymmetricAlgorithm;

            Debug.Assert(wrappedAlgorithm != null, "Logged authenticated algorithm did not wrap into an authenticated algortihm");
            return wrappedAlgorithm;
        }

        /// <summary>
        ///     Get the last encryption state from an algorithm logged with an AuthenticatedSymmetricAlgorithmLogger.
        /// </summary>
        public static AuthenticatedSymmetricEncryptionState GetLastEncryptionState(this AuthenticatedSymmetricAlgorithm loggedAlgorithm)
        {
            AuthenticatedSymmetricAlgorithmLogger logger = loggedAlgorithm as AuthenticatedSymmetricAlgorithmLogger;

            if (logger == null)
                throw new InvalidOperationException(Properties.Resources.EncryptionStateRequiresSymetricAlgorithmLogger);

            return logger.LastEncryptionState;
        }
    }
#endif // !FXONLY_BUILD
}
