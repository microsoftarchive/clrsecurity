# Security.Principal.LogOnType

{"The LogOnType enumeration contains the types of logon operations that may be performed."} 

| None | {"No logon type - this is not a valid logon type to use with LogonUser"}  |
| Interactive | {"Logon as an interactive user, which may cause additional caching and therefore not be appropriate for some server scenarios. This is equivalent to the LOGON32_LOGON_INTERACTIVE logon type."}  |
| Network | {"Logon type for servers to check cleartext passwords. No caching is done for this type of logon. This is equivalent to the LOGON32_LOGON_NETWORK logon type."}  |
| Batch | {"Logon type for servers who act on behalf of users without their intervention, or who processs many cleartext passwords at time. This is equivalent to the LOGON32_LOGON_BATCH logon type."}  |
| Service | {"Logon as a service. The account being logged on must have privilege to act as a service. This is equivalent to the LOGON32_LOGON_SERVICE logon type."}  |
| Unlock | {"Logon type for GINA DLLs to unlock the machine with. This is equivalent to the LOGON32_LOGON_UNLOCK logon type."}  |
| NetworkClearText | {"Logon type which allows caching of the text password in the authentication provider in order to allow connections to multiple network services with the same credentials. This is equivalent to the LOGON32_LOGON_NETWORK_CLEARTEXT logon type."}  |
| NewCredentials | {"Logon type which creates a token with the same identity as the current user token for the local proces, but provides new credentials for outbound network connections. This is equivalent to the LOGON32_LOGON_NEW_CREDENTIALS logon type."}  |
