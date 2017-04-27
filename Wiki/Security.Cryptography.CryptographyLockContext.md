# Security.Cryptography.CryptographyLockContext<T>

A cryptography lock context object is used as a parameter to cryptographic diagnostic code that is ensuring that all the proper locks are held when a cryptographic object is used from multiple threads.  The type parameter is the type of algorithm that the callback is being used with.  For instance, when doing symmetric algorithm verification, the type parameter will be SymmetricAlgorithm.

## APIs

### T CryptographyLockContext::Algorithm { get; }

Gets the algorithm that is being checked for correct multithreaded access

### object CryptographyLockContext::Parameter { get; }

Gets an optional parameter given by the diagnostic setup code to the verification code.  For symmetric algorithm verification, this value comes from the value specified in the LockCheckParameter property of the SymmetricAlgorithmDiagnosticOptions object used to setup logging.
