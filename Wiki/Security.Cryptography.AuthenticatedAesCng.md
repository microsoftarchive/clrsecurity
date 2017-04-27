# Security.Cryptography.AuthenticatedAesCng

{""} 
{"The AuthenticatedAesCng class provides a wrapper for the CNG implementation of the authenticated AES algorithm. AesCng uses the BCrypt layer of CNG to do its work, and requires Windows Vista SP1 and the .NET Framework 3.5."} 
 {""} 
More information on using AuthenticatedAesCng can be found here: [http://blogs.msdn.com/shawnfa/archive/2009/03/17/authenticated-symmetric-encryption-in-net.aspx](http://blogs.msdn.com/shawnfa/archive/2009/03/17/authenticated-symmetric-encryption-in-net.aspx) 
 {""} 
{"Since most of the AuthenticatedAesCng APIs are inherited from the"} [Security.Cryptography.AuthenticatedSymmetricAlgorithm](Security.Cryptography.AuthenticatedSymmetricAlgorithm) {"base class, see the documentation for AuthenticatedSymmetricAlgorithm for a complete API description."} 
 {""} 
{"Example usage - encrypting and authenticating data using GCM"} {{
// Encrypt and authenticate data stored in byte array plaintext, using a key and IV.
// Additionally, provide data that is required to validate the authentication tag, but
// which does not get added into the ciphertext.
using (AuthenticatedAesCng aes = new AuthenticatedAesCng())
{
    aes.Key = GetEncryptionKey();
    aes.IV = GetNonce();
    aes.CngMode = CngChainingMode.Gcm;
            
    // This data is required to verify the authentication tag, but will not go into the
    // ciphertext
    aes.AuthenticatedData = GetAdditionalAuthenticationData();
            
    // Do the encryption
    using (MemoryStream ms = new MemoryStream())
    using (IAuthenticatedCryptoTransform encryptor = aes.CreateAuthenticatedEncryptor())
    using (CryptoStream cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
    {
        // Encrypt the plaintext
        byte[]() plaintext = GetPlaintext();
        cs.Write(paintext, 0, paintext.Length);
            
        // Complete the encryption operation, and generate the authentication tag
        cs.FlushFinalBlock();
            
        // Get the generated ciphertext and authentication tag
        byte[]() ciphertext = ms.ToArray();
        byte[]() authenticationTag = encryptor.GetTag();
    }
}

}}
 {""} 
 {""} 
{"Example usage - Decrypting and verifying data using GCM"} {{
// Decrypt and authenticate data stored in byte array ciphertext, using a key and IV. 
// Additionally, provide data that is required to validate the authentication tag, but
which does not get added into the ciphertext.
using (AuthenticatedAesCng aes = new AuthenticatedAesCng())
{
    aes.Key = GetEncryptionKey();
    aes.IV = GetNonce();
    aes.CngMode = CngChainingMode.Gcm;
            
    // This data is required to verify the authentication tag, but will not go into the
    // ciphertext
    aes.AuthenticatedData = GetAdditionalAuthenticationData();
            
    // The authentication tag was generated during the encryption operation.
    aes.Tag = GetAuthenticationTag();
            
    // Do the decryption and authentication
    using (MemoryStream ms = new MemoryStream())
    using (ICryptoTransform decryptor = aes.CreateDecryptor())
    using (CryptoStream cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Write))
    {
        // Decrypt the ciphertext
        byte[]() ciphertext = GetCiphertext();
        cs.Write(ciphertext, 0, ciphertext.Length);
            
        // If the authentication tag does not validate, this call will throw a
        // CryptographicException.
        cs.FlushFinalBlock();
            
        // Get the decrypted and authenticated plaintext
        byte[]() decrypted = ms.ToArray();
    }
}

}}
 {""} 
 {""} 

## APIs

### .ctor([System.Security.Cryptography.CngProvider](http://msdn.microsoft.com/en-us/library/system.security.cryptography.cngprovider.aspx) provider)

{"Construct an AuthenticatedAesCng using a specific algorithm provider. The default settings for this object are:"} 
* {"CngMode - CngChainingMode.Gcm"} 
 {""} 

**Parameters:**
| provider | {"algorithm provider to use for AES computation"}  |

**Exceptions:**
| [System.ArgumentNullException](http://msdn.microsoft.com/en-us/library/system.argumentnullexception.aspx) | {"if"} _provider_ {"is null"}  |


### bool ChainingSupported { get; }

{"Gets a value determining if the AES object supports chaining multiple encryption calls, or if all encryption or decryption must be done at once. Generally, this value won't matter to code running against the AuthenticatedAesCng object, since the transforms produced by AuthenticatedAesCng will take chaining support into account to ensure that only one call to CNG is made if that is required."} 

### [Security.Cryptography.CngChainingMode](Security.Cryptography.CngChainingMode) CngMode { get; set; }

{"Gets or sets the CNG cipher mode to use during encryption or decryption. This mode must be an authenticating chaining mode, currently:"} 
* {"CngChainingMode.Ccm"} 
* {"CngChainingMode.Gcm"} 
 {""} 

