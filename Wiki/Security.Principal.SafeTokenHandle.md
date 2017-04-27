# Security.Principal.SafeTokenHandle


SafeHandle class for a Win32 HANDLE representing a windows token. This class can be used instead of the raw IntPtr returned from [System.Security.Principal.WindowsIdentity.Token](http://msdn.microsoft.com/en-us/library/system.security.principal.windowsidentity.token.aspx) in order to prevent the WindowsIdentity object from closing out the hande from underneath you if it is garbage collected before your use of the handle is complete. 
 
A SafeTokenHandle for a WindowsIdentity can be obtained by calling the [System.Security.Principal.WindowsIdentity](System.Security.Principal.WindowsIdentity).GetSafeTokenHandle() extension method. 
