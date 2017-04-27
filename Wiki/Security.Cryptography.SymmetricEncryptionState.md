# Security.Cryptography.SymmetricEncryptionState

A SymmetricEncryptionState object is an opaque object that contains information about the various parameters used to encrypt some data.  This object contains sensitive information, such as the key used for encryption, and as such should not be used in shipping code.  Instead, it should only be used while diagnosing problems with encryption code.

SymmetricEncryptionState objects are serializable, so you can use serialization to send them to other processes or AppDomains if your encryption crosses domain boundaries.  They are also Disposable, with a dispose implementation that zeros out any sensitive information held in the object.

## APIs

## SymmetricEncryptionState SymmetricEncryptionState::Clone()

Create a deep clone of the encryption state object.

### SymmetricEncryptionState::Dispose()

Clears out any sensitive state held within the encryption state object.