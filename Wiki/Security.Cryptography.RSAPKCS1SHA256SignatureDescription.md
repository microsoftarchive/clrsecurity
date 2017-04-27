# Security.Cryptography.RSAPKCS1SHA256SignatureDescription

{""} 
The RSAPKCS1SHA256SignatureDescription class provides a signature description implementation for RSA-SHA256 signatures. It allows XML digital signatures to be produced using the [http://www.w3.org/2001/04/xmldsig-more#rsa-sha256](http://www.w3.org/2001/04/xmldsig-more#rsa-sha256) signature type. RSAPKCS1SHA256SignatureDescription provides the same interface as other signature description implementations shipped with the .NET Framework, such as [System.Security.Cryptography.RSAPKCS1SHA1SignatureDescription](http://msdn.microsoft.com/en-us/library/system.security.cryptography.rsapkcs1sha1signaturedescription.aspx) {"."} 
 {""} 
{"RSAPKCS1SHA256SignatureDescription is not generally intended for use on its own, instead it should be consumed by higher level cryptography services such as the XML digital signature stack. It can be registered in"} [System.Security.Cryptography.CryptoConfig](http://msdn.microsoft.com/en-us/library/system.security.cryptography.cryptoconfig.aspx) {"so that these services can create instances of this signature description and use RSA-SHA256 signatures."} 
 {""} 
{"Registration in CryptoConfig requires editing the machine.config file found in the .NET Framework installation's configuration directory (such as %WINDIR%\Microsoft.NET\Framework\v2.0.50727\Config or %WINDIR%\Microsoft.NET\Framework64\v2.0.50727\Config) to include registration information on the type. For example:"} 
 {""} {{
<configuration>
  <mscorlib>
    <!-- ... -->
    <cryptographySettings>
      <cryptoNameMapping>
        <cryptoClasses>
          <cryptoClass RSASHA256SignatureDescription="Security.Cryptography.RSAPKCS1SHA256SignatureDescription, Security.Cryptography, Version=1.1.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35" />
        </cryptoClasses>
        <nameEntry name="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" class="RSASHA256SignatureDescription" />
      </cryptoNameMapping>
    </cryptographySettings>
  </mscorlib>
</configuration>

}}
 {""} 
{"After adding this registration entry, the assembly which contains the RSAPKCS1SHA256SignatureDescription (in the example above Security.Cryptography.dll) needs to be added to the GAC."} 
 {""} 
{"Note that on 64 bit machines, both the Framework and Framework64 machine.config files should be updated, and if the signature description assembly is built bit-specific it needs to be added to both the 32 and 64 bit GACs."} 
 {""} 
{"RSA-SHA256 signatures are first available on the .NET Framework 3.5 SP 1 and as such the RSAPKCS1SHA256SignatureDescription requires .NET 3.5 SP 1 and Windows Server 2003 or greater to work properly."} 
 {""} 
{"On Windows 2003, the default OID registrations are not setup for the SHA2 family of hash algorithms, and this can cause the .NET Framework v3.5 SP 1 to be unable to create RSA-SHA2 signatures. To fix this problem, the"} [Security.Cryptography.Oid2.RegisterSha2OidInformationForRsa](Security.Cryptography.Oid2.RegisterSha2OidInformationForRsa) {"method can be called to create the necessary OID registrations."} 
 {""} 

## APIs

### .ctor()

{"Construct an RSAPKCS1SHA256SignatureDescription object. The default settings for this object are:"} 
* {"Digest algorithm -"} [System.Security.Cryptography.SHA256Managed](http://msdn.microsoft.com/en-us/library/system.security.cryptography.sha256managed.aspx) 
* {"Key algorithm -"} [System.Security.Cryptography.RSACryptoServiceProvider](http://msdn.microsoft.com/en-us/library/system.security.cryptography.rsacryptoserviceprovider.aspx) 
* {"Formatter algorithm -"} [System.Security.Cryptography.RSAPKCS1SignatureFormatter](http://msdn.microsoft.com/en-us/library/system.security.cryptography.rsapkcs1signatureformatter.aspx) 
* {"Deformatter algorithm -"} [System.Security.Cryptography.RSAPKCS1SignatureDeformatter](http://msdn.microsoft.com/en-us/library/system.security.cryptography.rsapkcs1signaturedeformatter.aspx) 
 {""} 


