# System.Security.Policy.Evidence

EvidenceExtensionMethods provides several extension methods for the [System.Security.Policy.Evidence](http://msdn.microsoft.com/en-us/library/system.security.policy.evidence.aspx) class. This type is in the Security.Policy namespace (not the System.Security.Policy namespace), so in order to use these extension methods, you will need to make sure you include this namespace as well as a reference to Security.dll. 

## APIs

### T GetAssemblyEvidence<T>()

Get the first evidence object of type _T_ supplied by the assembly that the Evidence collection is for. 

**Generic Parameters:**
| T | Type of assembly evidence that should be obtained.  |

**Return Value:**
The first evidence object of type _T_ that is in the assembly supplied evidence, or null if the assembly has not supplied any evidence of type _T_ . 


### T GetHostEvidence<T>()

Get the first evidence object of type _T_ supplied by the host in the Evidence collection. 

**Generic Parameters:**
| T | Type of host evidence that should be obtained.  |

**Return Value:**
The first evidence object of type _T_ that is in the host supplied evidence, or null if the host has not supplied any evidence of type _T_ . 
