# System.Security.Cryptography.SymmetricAlgorithm

Several extension methods for the [SymmetricAlgorithm](http://msdn.microsoft.com/en-us/library/system.security.cryptography.symmetricalgorithm.aspx) class are provided in the SymmetricAlgorihmExtensionMethods type.  This type is in the Security.Cryptography namespace (not the System.Security.Cryptography namespace), so in order to use these extension methods, you will need to make sure you include this namespace as well as a reference to [Security.Cryptography.Debug.dll](Security.Cryptography.Debug.dll).

## APIs

### [SymmetricAlgorithm](http://msdn.microsoft.com/en-us/library/system.security.cryptography.symmetricalgorithm.aspx) SymmetricAlgorithm::EnableLogging()
Creates a symmetric algorithm object that will log all of the input parameters to encryption and allow access to a SymmetricEncryptionState object that will enable decryption verification.  The symmetric algorithm created with this method will not check for correct multi-threaded access to an encryption object.

### [SymmetricAlgorithm](http://msdn.microsoft.com/en-us/library/system.security.cryptography.symmetricalgorithm.aspx) SymmetricAlgorithm::EnableLogging([Security.Cryptography.SymmetricAlgorithmDiagnosticOptions](Security.Cryptography.SymmetricAlgorithmDiagnosticOptions) diagnosticOptions)
_Arguments:_
| diagnosticOptions | options for customizing the diagnostic logging |

_Exceptions:_
| ArgumentNullException | if _diagnosticOptions_ is null |

Creates a symmetric algorithm object that will log all of the input parameters to encryption and allow access to a SymmetricEncryptionState object that will enable decryption verification.

### [SymmetricAlgorithm](http://msdn.microsoft.com/en-us/library/system.security.cryptography.symmetricalgorithm.aspx) SymmetricAlgorithm::EnableDecryptionVerification([Security.Cryptography.SymmetricEncryptionState](Security.Cryptography.SymmetricEncryptionState) encryptionState)
_Arguments:_
| encryptionState | diagnostic state captured during the encryption operation |

_Exceptions:_
| ArgumentNullException | if _encryptionState_ is null |

Creates a symmetric algorithm object that will throw a CryptographicDiagnosticException if decryption parameters do not match up with the _encryptionState_ values.  The symmetric algorithm created with this method will not check for correct multi-threaded access to a decryption object.

### [SymmetricAlgorithm](http://msdn.microsoft.com/en-us/library/system.security.cryptography.symmetricalgorithm.aspx) SymmetricAlgorithm::EnableDecryptionVerification([Security.Cryptography.SymmetricEncryptionState](Security.Cryptography.SymmetricEncryptionState) encryptionState, [Security.Cryptography.SymmetricAlgorithmDiagnosticOptions](Security.Cryptography.SymmetricAlgorithmDiagnosticOptions) diagnosticOptions)
_Arguments:_
| encryptionState | diagnostic state captured during the encryption operation |
| diagnosticOptions | options for customizing the diagnostic logging |

_Exceptions:_
| ArgumentNullException | if _encryptionState_ or _diagnosticOptions_ are null |

Creates a symmetric algorithm object that will throw a CryptographicDiagnosticException if decryption parameters do not match up with the _encryptionState_ values.

### [Security.Cryptography.SymmetricEncryptionState](Security.Cryptography.SymmetricEncryptionState) SymmetricAlgorithm::GetLastEncryptionState()
_Exceptions:_
| InvalidOperationException | if the algorithm that GetLastEncryptionState is called on was not returned by one of the EnableLogging methods, or if an encryptor has not yet been created by the logged algorithm |

Gets the most current encryption state that was used to create an encryptor for a logged symmetric algorithm.  This object can be passed to the EnableDecryptionVerification method in order to enable checking that the decryption parameters match the encryption parameters.
