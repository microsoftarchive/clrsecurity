# Security.StandardPermissionSet

{"The StandardPermissionSet enumeration identifies the standard built-in permission sets that the CLR uses."} 

| Nothing | {"The empty permission set"}  |
| Execution | {"A permission set which only contains permission to execute"}  |
| Internet | {"A permission set which is safe to grant applications from the Internet."}  |
| LocalIntranet | {"A permission set which is safe to grant applications from the local network."}  |
| Everything | {"The Everything permission set contains unrestricted versions of all built in permissions, with the exception of SecurityPermission which does not contain the skip verification flag. This permission set should not be used as a sandbox, and is generally interesting only for testing purposes."}  |
| FullTrust | {"The FullTrust permission set is a superset of all other permission sets."}  |
