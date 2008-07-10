// Copyright (c) Microsoft Corporation.  All rights reserved.

using System;
using System.Security.Cryptography;

namespace Security.Cryptography
{
    /// <summary>
    ///     Extension methods for the SymmetricAlgorithm class which enable setting up logging and verification
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

            return new SymmetricAlgorithmLogger(loggedAlgorithm,
                                                options.CheckThreadSafety ? options.LockCheckCallback : null,
                                                options.CheckThreadSafety ? options.LockCheckParameter : null);
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

            return new SymmetricAlgorithmVerifier(loggedAlgorithm,
                                                  encryptionState,
                                                  options.CheckThreadSafety ? options.LockCheckCallback : null,
                                                  options.CheckThreadSafety ? options.LockCheckParameter : null);
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
