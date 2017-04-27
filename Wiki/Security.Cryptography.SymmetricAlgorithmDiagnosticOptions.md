# Security.Cryptography.SymmetricAlgorithmDiagnosticOptions

SymmetricAlgorithmDiagnosticOptions allows customization of the verification process for symmetric algorithm encryption.  Currently it allows code to hook accesses to the symmetric algorithm in order to ensure that they are done properly with regards to multiple threads.

## APIs

### bool SymmetricAlgorithmDiagnosticOptions::CheckThreadSafety { get; set; }

Gets or sets a value that determines if cryptographic verification should include multi-thread checks.  The default value is false.

### Predicate<CryptographyLockContext<SymmetricAlgorithm>> SymmetricAlgorithmDiagnosticOptions::LockCheckCallback { get; set; }

Gets or sets the predicate to callback during multi-thread accesses.  This property is not used if CheckThreadSafety is false.  The predicate supplied will be called on the same thread as the current attempt to access the cryptography object is occurring on, and should return true if the access to the encryption algorithm is safe; false otherwise.  

### object SymmetricAlgorithmDiagnosticOptions::LockCheckParameter { get; set; }

Gets or sets an optional parameter to include as the Parameter property of the CryptographyLockContext object supplied to the LockCheckCallback predicate.  This value is not used of CheckThreadSafety is set to false.

### Example Usage:

To setup multi-thread verification of your encryption code, you would configure code such as:

{{
    ReaderWriterLock encryptionMutex = new ReaderWriterLock(); // The writer lock should be held by anyone attempting to use the shared encryption object;

    SymmetricAlgorithmDiagnosticOptions diagnosticOptions = new SymmetricAlgorithmDiagnosticOptions();
    diagnosticOptions.CheckThreadSafety = true;
    diganosticOptions.LockCheckParameter = encryptionMutex;
    diagnosticOptions.LockCheckCallback = delegate(CryptographyLockContext<SymmetricAlgorithm> lockCheck)
    {
        ReaderWriterLock lock = lockCheck.Parameter as ReaderWriterLock;
        return lock != null && lock.IsWriterLockHeld;
    }

    SymmetricAlgorithm aes = new AesManaged().EnableLogging(diagnosticOptions);
}}