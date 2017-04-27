# Security.Cryptography.Debug.dll

One of the more frustrating problems when using the .NET Framework cryptography libraries is a CryptographicException complaining about "Padding is invalid and cannot be removed."  Since this exception can be caused by a mismatch of any one of a number of encryption parameters, tracking down the root cause of the problem can be difficult.  Security.Cryptography.Debug.dll provides a set of classes to help you automatically debug such exceptions and determine exactly what went wrong in the first place.

The debug interface monitors the state of your encryption operation and stores this information in an opaque SymmetricEncryptionState object.  On the decryption side, you simply provide this SymmetricEncryptionState object to the decryption operation and it makes sure that everything lines up property.  If any error is detected, it will throw a CryptographicDiagnosticException with details about exactly what parameters didn't match on both ends of the operation.

You can wire up your encryption logging through a set of extension methods to the SymmetricAlgorithm base class, which provide an easy way for you to seamlessly drop diagnostics into your existing code with minimal modifications.  For more advanced uses, such as catching incorrect multi-threaded access (for instance accessing a crypto object without holding the correct lock), there is a more rich API that can be programmed against.

Of course, since at its core these diagnostic operations are keeping track of sensitive data such as plaintext and keys, the Security.Cryptography.Debug.dll should never be wired up in any shipping code.  Its proper use is for debugging applications still in development, and you should never have SymmetricEncryptionState objects left in your final code.

## Download
[release:24868](release_24868)

## Example Use

The following encryption / decryption code will end up throwing the infamous invalid padding exception:

{{
    // Encryption code
    using (AesManaged aes = new AesManaged())
    {
        aes.Key = GetKey();

        using (MemoryStream ms = new MemoryStream())
        using (CryptoStream cs = new CryptoStream(ms, aes.CreateEncryptor(), CryptoStreamMode.Write))
        {
            cs.Write(plainText, 0, plainText.Length);
            cs.FlushFinalBlock();
            cipherText = ms.ToArray();
        }
    }

   //
   // ...
   //

    // Decryption Code
    using (AesManaged aes = new AesManaged())
    {
        aes.Key = GetKey();

        using (MemoryStream ms = new MemoryStream())
        using (CryptoStream cs = new CryptoStream(ms, aes.CreateDecryptor(), CryptoStreamMode.Write))
        {
            cs.Write(cipherText, 0, cipherText.Length);
            cs.FlushFinalBlock();
            recoveredPlainText = ms.ToArray();
        }
    }
}}

In this case, we didn't supply an IV when creating our encryption and decryption AES objects, which means that they both generated random IVs.  This will lead to an invalid padding exception when the decryption AES object realizes that the final block of code is not padded with valid PKCS #7 padding.

In order to debug the problem, we can wire up the Security.Cryptography.Debug.dll library.  After we've added a reference to the debug assembly, and included the Security.Cryptography namespace in our code, the first step is to enable logging on the encryption AES object.  This is done by calling the EnableLogging() extension method, and replacing our current AES object with the return value:

{{
    // Encryption code
    using (SymmetricAlgorithm aes = new AesManaged().EnableLogging())
}}

Now that the logging is attached, the rest of the encryption code proceeds as normal.  When we've finshed encrypting our data, we then need to grab the SymmetricEncryptionState object that tracked the current encryption parameters.  This is done by calling the GetLastEncryptionState extension method:

{{
    // Encryption code
    SymmetricAlgorithmState encryptionState = null;
    using (SymmetricAlgorithm aes = new AesManaged().EnableLogging())
    {
        aes.Key = GetKey();

        using (MemoryStream ms = new MemoryStream())
        using (CryptoStream cs = new CryptoStream(ms, aes.CreateEncryptor(), CryptoStreamMode.Write))
        {
            cs.Write(plainText, 0, plainText.Length);
            cs.FlushFinalBlock();
            cipherText = ms.ToArray();
        }

        encryptionState = aes.GetLastEncryptionState();
    }
}}

Attaching to the decryption code follows a similar flow.  First, we need to enable decryption verification on our decryption code in the same way we setup logging on the encryption algorithm.  This is done by calling the EnableDecryptionVerification extension method and supplying it with the SymmetricEncryptionState object that was obtained during the encryption logging.

{{
    // Decryption Code
    using (SymmetricAlgorithm aes = new AesManaged().EnableDecryptionVerification(encryptionState))
}}

Now that decryption verification is enabled, the rest of the decryption code proceeds unmodified:

{{
    // Decryption Code
    using (SymmetricAlgorithm aes = new AesManaged().EnableDecryptionVerification(encryptionState))
    {
        aes.Key = GetKey();

        using (MemoryStream ms = new MemoryStream())
        using (CryptoStream cs = new CryptoStream(ms, aes.CreateDecryptor(), CryptoStreamMode.Write))
        {
            cs.Write(cipherText, 0, cipherText.Length);
            cs.FlushFinalBlock();
            recoveredPlainText = ms.ToArray();
        }
    }
}}

When this code runs, instead of getting an invalid padding CryptographicException, we get a CryptographicDiagnosticException with a message similar to:
{{
IV mismatch.
    Encryption: (128 bits): 0123456789abcdef...
    Decryption:  (128 bits): fedcba9876543210...
}}

This new information provides us the hint that we needed - the encryption and decryption operations were operating with different initialization vectors, and when we go back and look at the original code we'll see that we need to ensure that they both work with the same IV.

Similar changes work for authenticated symmetric algorithms - simply enable logging on the authenticated symmetric algorithm object:

{{
    // Encryption code
    using (AuthenticatedSymmetricAlgorithm aes = new AuthenticatedAesCng().EnableLogging())
}}

And use it exactly as you would have before.  Similarly, on the decryption side, just enable verification with the encrytion state retrieved from the encryption logging:

{{
    // Decryption Code
    using (AuthenticatedSymmetricAlgorithm aes = new AuthenticatedAesCng().EnableDecryptionVerification(encryptionState))
}}

Note that to use Security.Cryptography.Debug on authenticated symmetric algorithms the Full package must be downloaded.  If you are building the debug library from sources, then the Debug and Release configurations enable debugging of AuthenticatedSymmetricAlgorithm objects, however the Release_FxOnly configuration does not.  Both the Debug and Release configurations require that Security.Cryptography.dll be available to reference during the build.

For more advanced uses, see the documentation for the [Security.Cryptography.SymmetricAlgorithmDiagnosticOptions](Security.Cryptography.SymmetricAlgorithmDiagnosticOptions) type.

## Class Reference
**[Security.Cryptography.AuthenticatedSymmetricEncryptionState](Security.Cryptography.AuthenticatedSymmetricEncryptionState)** - Opaque object that holds onto the information logged by the AuthenticatedSymmetricAlgorithmLogger
**[Security.Cryptography.CryptographyLockContext](Security.Cryptography.CryptographyLockContext)** - Provides information to help advanced diagnostic code ensure that proper locks are held when using cryptography from multiple threads
**[Security.Cryptography.SymmetricAlgorithmDiagnosticOptions](Security.Cryptography.SymmetricAlgorithmDiagnosticOptions)** - Allows customization of the checks done during diagnosis
**[Security.Cryptography.SymmetricEncryptionState](Security.Cryptography.SymmetricEncryptionState)** - Opaque object that holds onto the information logged by the SymmetricAlgorithmLogger

**[Security.Cryptography.AuthenticatedSymmetricAlgorithm(Security.Cryptography.Debug)](Security.Cryptography.AuthenticatedSymmetricAlgorithm(Security.Cryptography.Debug))** - A set of extension methods for the AuthenticatedSymmetricAlgorithm type
**[System.Security.Cryptography.SymmetricAlgorithm](System.Security.Cryptography.SymmetricAlgorithm)** - A set of extension methods for the SymmetricAlgorithm type
