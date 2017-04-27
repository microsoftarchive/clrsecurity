# Security.Cryptography.AuthenticatedSymmetricAlgorithm

Several extension methods for the [Security.Cryptography.AuthenticatedSymmetricAlgorithm](Security.Cryptography.AuthenticatedSymmetricAlgorithm) class are provided in the AuthenticatedSymmetricAlgorihmExtensionMethods type. 

## APIs

### [Security.Cryptography.AuthenticatedSymmetricAlgorithm](Security.Cryptography.AuthenticatedSymmetricAlgorithm) AuthenticatedSymmetricAlgorithm::EnableLogging()
Creates an authenticated symmetric algorithm object that will log all of the input parameters to encryption and allow access to a AuthenticatedSymmetricEncryptionState object that will enable decryption verification.  The authenticated symmetric algorithm created with this method will not check for correct multi-threaded access to an encryption object.

### [Security.Cryptography.AuthenticatedSymmetricAlgorithm](Security.Cryptography.AuthenticatedSymmetricAlgorithm) AuthenticatedSymmetricAlgorithm::EnableLogging([Security.Cryptography.SymmetricAlgorithmDiagnosticOptions](Security.Cryptography.SymmetricAlgorithmDiagnosticOptions) diagnosticOptions)
_Arguments:_
| diagnosticOptions | options for customizing the diagnostic logging |

_Exceptions:_
| ArgumentNullException | if _diagnosticOptions_ is null |

Creates an authenticated symmetric algorithm object that will log all of the input parameters to encryption and allow access to a AuthenticatedSymmetricEncryptionState object that will enable decryption verification.

### [Security.Cryptography.AuthenticatedSymmetricAlgorithm](Security.Cryptography.AuthenticatedSymmetricAlgorithm) AuthenticatedSymmetricAlgorithm::EnableDecryptionVerification([Security.Cryptography.AuthenticatedSymmetricEncryptionState](Security.Cryptography.AuthenticatedSymmetricEncryptionState) encryptionState)
_Arguments:_
| encryptionState | diagnostic state captured during the encryption operation |

_Exceptions:_
| ArgumentNullException | if _encryptionState_ is null |

Creates an authenticated symmetric algorithm object that will throw a CryptographicDiagnosticException if decryption parameters do not match up with the _encryptionState_ values.  The authenticated symmetric algorithm created with this method will not check for correct multi-threaded access to a decryption object.

### [Security.Cryptography.AuthenticatedSymmetricAlgorithm](Security.Cryptography.AuthenticatedSymmetricAlgorithm) AuthenticatedSymmetricAlgorithm::EnableDecryptionVerification([Security.Cryptography.AuthenticatedSymmetricEncryptionState](Security.Cryptography.AuthenticatedSymmetricEncryptionState) encryptionState, [Security.Cryptography.SymmetricAlgorithmDiagnosticOptions](Security.Cryptography.SymmetricAlgorithmDiagnosticOptions) diagnosticOptions)
_Arguments:_
| encryptionState | diagnostic state captured during the encryption operation |
| diagnosticOptions | options for customizing the diagnostic logging |

_Exceptions:_
| ArgumentNullException | if _encryptionState_ or _diagnosticOptions_ are null |

Creates an authenticated symmetric algorithm object that will throw a CryptographicDiagnosticException if decryption parameters do not match up with the _encryptionState_ values.

### [Security.Cryptography.AuthenticatedSymmetricEncryptionState](Security.Cryptography.AuthenticatedSymmetricEncryptionState) AuthenticatedSymmetricAlgorithm::GetLastEncryptionState()
_Exceptions:_
| InvalidOperationException | if the algorithm that GetLastEncryptionState is called on was not returned by one of the EnableLogging methods, or if an encryptor has not yet been created by the logged algorithm |

Gets the most current encryption state that was used to create an encryptor for a logged authenticated symmetric algorithm.  This object can be passed to the EnableDecryptionVerification method in order to enable checking that the decryption parameters match the encryption parameters.
