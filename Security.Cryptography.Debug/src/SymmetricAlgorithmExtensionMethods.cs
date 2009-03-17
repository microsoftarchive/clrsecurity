// Copyright (c) Microsoft Corporation.  All rights reserved.

using System;
using System.Security.Cryptography;
using Security.Cryptography.Properties;

namespace Security.Cryptography
{
    /// <summary>
    ///     Extension methods for the SymmetricAlgorithm class which enable setting up logging and
    ///     verification.
    ///     
    ///     These methods know how to wire up verifiers for both SymmetricAlgorithms as well as subtypes of
    ///     SymmetricAlgorithm that require their own special logging (for instance
    ///     AuthenticatedSymmetricAlgorithm).  The reason that we need to put that logic in the central
    ///     SymmetricAlgorithm extension methods rather than in the specific subtype extension methods is
    ///     that we want to be able to hook up the correct type of logging regardless of the static type of
    ///     the object reference being logged.
    ///     
    ///     For instance, if code creates an AuthenticatedSymmetricAlgorithm and stores it in a
    ///     SymmetricAlgorithm variable, that's perfectly legal from a object model standpoint.  However, if
    ///     that code then attempts to hook up a logger / verifier to the algorithm, it won't be keeping
    ///     track of any extra authenticated state.
    ///     
    ///     See code:System.Security.Cryptography.SymmetricAlgorithmLogger#SymmetricAlgorithmDiagnostics
    /// </summary>
    public static class SymmetricAlgorithmExtensionMethods
    {
        /// <summary>
        ///     Create a SymmetricAlgorithm which logs the encryption operation of the input algorithm, but
        ///     does not monitor for thread safe access to the object.
        /// </summary>
        public static SymmetricAlgorithm EnableLogging(this SymmetricAlgorithm loggedAlgorithm)
        {
            return loggedAlgorithm.EnableLogging(new SymmetricAlgorithmDiagnosticOptions() { CheckThreadSafety = false });
        }

        /// <summary>
        ///     Create a SymmetricAlgorithm which logs the encryption operation of the input algorithm
        /// </summary>
        public static SymmetricAlgorithm EnableLogging(this SymmetricAlgorithm loggedAlgorithm,
                                                       SymmetricAlgorithmDiagnosticOptions options)
        {
            if (options == null)
                throw new ArgumentNullException("options");

#if !FXONLY_BUILD
            AuthenticatedSymmetricAlgorithm authenticatedLoggedAlgorithm =
                loggedAlgorithm as AuthenticatedSymmetricAlgorithm;

            if (authenticatedLoggedAlgorithm != null)
            {
                return new AuthenticatedSymmetricAlgorithmLogger(authenticatedLoggedAlgorithm,
                                                                 options.CheckThreadSafety ? options.LockCheckCallback : null,
                                                                 options.CheckThreadSafety ? options.LockCheckParameter : null);
            }
            else
#endif // !FXONLY_BUILD
            {
                return new SymmetricAlgorithmLogger(loggedAlgorithm,
                                                    options.CheckThreadSafety ? options.LockCheckCallback : null,
                                                    options.CheckThreadSafety ? options.LockCheckParameter : null);
            }
        }

        /// <summary>
        ///     Create a SymmetricAlgorithm which verifies the decryption operations done on it have state
        ///     which matches captured encryption state. This overload does not monitor for thread safe
        ///     access to the object.
        /// </summary>
        public static SymmetricAlgorithm EnableDecryptionVerification(this SymmetricAlgorithm loggedAlgorithm,
                                                                      SymmetricEncryptionState encryptionState)
        {
            if (encryptionState == null)
                throw new ArgumentNullException("encryptionState");

            return loggedAlgorithm.EnableDecryptionVerification(encryptionState,
                                                                new SymmetricAlgorithmDiagnosticOptions() { CheckThreadSafety = false });
        }

        /// <summary>
        ///     Create a SymmetricAlgorithm which verifies the decryption operations done on it have state
        ///     which matches captured encryption state.
        /// </summary>
        public static SymmetricAlgorithm EnableDecryptionVerification(this SymmetricAlgorithm loggedAlgorithm,
                                                                      SymmetricEncryptionState encryptionState,
                                                                      SymmetricAlgorithmDiagnosticOptions options)
        {
            if (encryptionState == null)
                throw new ArgumentNullException("encryptionState");
            if (options == null)
                throw new ArgumentNullException("options");

#if !FXONLY_BUILD
            AuthenticatedSymmetricAlgorithm authenticatedLoggedAlgorithm =
                loggedAlgorithm as AuthenticatedSymmetricAlgorithm;

            if (authenticatedLoggedAlgorithm != null)
            {
                AuthenticatedSymmetricEncryptionState authenticatedEncryptionState =
                    encryptionState as AuthenticatedSymmetricEncryptionState;

                if (authenticatedEncryptionState == null)
                {
                    throw new ArgumentException(Resources.NeedAuthenticatedEncryptionState, "encryptionState");
                }

                return new AuthenticatedSymmetricAlgorithmVerifier(authenticatedLoggedAlgorithm,
                                                                   authenticatedEncryptionState,
                                                                   options.CheckThreadSafety ? options.LockCheckCallback : null,
                                                                   options.CheckThreadSafety ? options.LockCheckParameter : null);
            }
            else
#endif // !FXONLY_BUILD
            {
                return new SymmetricAlgorithmVerifier(loggedAlgorithm,
                                                      encryptionState,
                                                      options.CheckThreadSafety ? options.LockCheckCallback : null,
                                                      options.CheckThreadSafety ? options.LockCheckParameter : null);
            }
        }

        /// <summary>
        ///     Get the last encryption state from an algorithm logged with a SymmetricAlgorithmLogger.
        /// </summary>
        public static SymmetricEncryptionState GetLastEncryptionState(this SymmetricAlgorithm loggedAlgorithm)
        {
            SymmetricAlgorithmLogger logger = loggedAlgorithm as SymmetricAlgorithmLogger;

            if (logger == null)
                throw new InvalidOperationException(Properties.Resources.EncryptionStateRequiresSymetricAlgorithmLogger);

            return logger.LastEncryptionState;
        }
    }
}
