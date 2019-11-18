# XAdES (XML Advanced Electronic Signatures) for .NET

This class library is for sign digital signatures to XML document in XAdES format which using Basic Electronic Signature profile only.

In this class library, Using SHA512 Hash algorithm as a default for Digest message.

#### XMLDSIG Signature element with XAdES element
``` xml
<ds:Signature Id="xmldsig-uniqueId" 
    xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
    <ds:SignedInfo>
        <ds:CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315" />
        <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha512" />
        <ds:Reference Id="xmldsig-uniqueId-ref0" URI="">
            <ds:Transforms>
                <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature" />
            </ds:Transforms>
            <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha512" />
            <ds:DigestValue>0O9Qo3zrWG+nv1YxTTaVr1oT1QU9uYVpNnYxVf2q4q669gnunFb3cvgxsEhyx06XDWVBo6KJ5nnFopxirviqbA==</ds:DigestValue>
        </ds:Reference>
        <ds:Reference Type="http://uri.etsi.org/01903#SignedProperties" URI="#xmldsig-uniqueId-signedprops">
            <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha512"></ds:DigestMethod>
            <ds:DigestValue>TRrT6flWKDoZLdDkOwSEK9f3NFNIFEDf4G7Ilo8O23up2y0hY3ea7ohw/nwhubzCw1fPxCbTtHRjO5VQnaUuTA==</ds:DigestValue>
        </ds:Reference>
    </ds:SignedInfo>
    <ds:SignatureValue Id="xmldsig-uniqueId-sigvalue">KBl9BCvWDFgFvqcLjD+BC86gvTEXWzD7WigYJoX12K0hF1XZUaIsXJsvkI6b+HuqGDdjlm4f8cvVYn2rfVjtIaYTlGRfwPycUuWAywiCry7LqGOaqUfd/h8NlB787d7mRQhIO8qXhswk7Aybd6w8na/jKqVScN0DmyL4RZ4eyVOvexujMsrpMXgpvm659y73fcEng2hYXEpoSgdcC+o5DfMAts7VF5Uh731qJiyVjlWOprzkRiTe7zhb2Opw0EsousruwP5bHc1ENdpdoQoeCHyTG2qzJWsqTnjjeiX1B8tuylkqS29iuqM4xwqmSp1vcZcANodPgAD83KI9rbXTPQ==</ds:SignatureValue>
    <ds:KeyInfo>
        <ds:X509Data>
            <ds:X509Certificate>MIIFWDCCBECgAwIBAgISA4bdH5+aZjQzZyUltlC+35huMA0GCSqGSIb3DQEBCwUAMEoxCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1MZXQncyBFbmNyeXB0MSMwIQYDVQQDExpMZXQncyBFbmNyeXB0IEF1dGhvcml0eSBYMzAeFw0xOTEwMjIwNzQ0NDBaFw0yMDAxMjAwNzQ0NDBaMBUxEzARBgNVBAMTCnVuZG9uZS5hcHAwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDGVfk7c9zQ097NKW1DvgARjox6y5zCOAt4XwqgMa3eWoSdO7kHKDmu0Uo9DpGcG6UFRTwa0jo1O/LzIM6jEdjtpI1XnRc+lDvMpKOJrPyoWfhXTl44rS18e+o+BM9Xwx6TYJ4cbvtyCZI81+HRCW/tKUNgqoMnvymGEd+6OA/CIvkLQZDSwOiG8UtN8C0KjJEpKtUDRKF2g19vQ6ZG8wHmIrag6vXunELxw1HcNzUmbCGs1o83Wqf/FXNC36wKrDlcBH4alX1D4MJjRIETAZeWmyQOXS3lp96lyeV4I49CVsUjlmb9ePcvsuvqsXp0EGAkJAhFCO+JNcw7H6hwR/OLAgMBAAGjggJrMIICZzAOBgNVHQ8BAf8EBAMCBaAwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMAwGA1UdEwEB/wQCMAAwHQYDVR0OBBYEFPPwwZ+9cjdukHQVeAzl65462WcmMB8GA1UdIwQYMBaAFKhKamMEfd265tE5t6ZFZe/zqOyhMG8GCCsGAQUFBwEBBGMwYTAuBggrBgEFBQcwAYYiaHR0cDovL29jc3AuaW50LXgzLmxldHNlbmNyeXB0Lm9yZzAvBggrBgEFBQcwAoYjaHR0cDovL2NlcnQuaW50LXgzLmxldHNlbmNyeXB0Lm9yZy8wIwYDVR0RBBwwGoIMKi51bmRvbmUuYXBwggp1bmRvbmUuYXBwMEwGA1UdIARFMEMwCAYGZ4EMAQIBMDcGCysGAQQBgt8TAQEBMCgwJgYIKwYBBQUHAgEWGmh0dHA6Ly9jcHMubGV0c2VuY3J5cHQub3JnMIIBAgYKKwYBBAHWeQIEAgSB8wSB8ADuAHUAb1N2rDHwMRnYmQCkURX/dxUcEdkCwQApBo2yCJo32RMAAAFt8qO99wAABAMARjBEAiAzdRFI+c+l8+QQ+ZumEGqnoAsN6CHI7yCRKBrKTQl9bAIgcJ3yDniNRDpgFyLDl2HwuKh5TNNF9WoayLtUtEiwpXIAdQAHt1wb5X1o//Gwxh0jFce65ld8V5S3au68YToaadOiHAAAAW3yo72zAAAEAwBGMEQCIGv9m2nHBx5GZPV9ztIJOtO56N0AUPsyj1DYPtscU9ocAiBJhIK3ASRVWvG5WhUKoVOjBHl5C4XNX44vOTCsmrqDczANBgkqhkiG9w0BAQsFAAOCAQEAFHbafM6WI77jN4/134bI8HO+TiypsWSwMS6fyEGyfRzQpDBU5nKfOM7RlGq8PcHj414ggZH5tvzn1aIcA//Zi11tUyPeAjgeRdmySiDN1wWpDEISS5Jek9jqT79mpJ+xx1PhONxGIsjKrGNc3lkzuaZ8HFcNRshom3MtCwHGnC8d4ETop1hZ22RUL1FFT9mtAhjYa8eSRXnPJff5IW8orOIyokEV6Wdj65LNgck6AdHxeLaBLVRBBiM5m7pbhQYbY7wde5c0R5Yk0/KQO1aHbNGiVUly5Cp/1RVB4j9nUnXPDCdqmGgJMNqkkPQ+OnOSmyF/fdchGFAjXw4+65bRAg==</ds:X509Certificate>
        </ds:X509Data>
    </ds:KeyInfo>
    <ds:Object>
        <xades:QualifyingProperties Target="#xmldsig-uniqueId" 
            xmlns:xades141="http://uri.etsi.org/01903/v1.4.1#" 
            xmlns:xades="http://uri.etsi.org/01903/v1.3.2#">
            <xades:SignedProperties Id="xmldsig-uniqueId-signedprops">
                <xades:SignedSignatureProperties>
                    <xades:SigningTime>2019-11-05T17:00:00Z</xades:SigningTime>
                    <xades:SigningCertificate>
                        <xades:Cert>
                            <xades:CertDigest>
                                <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha512"></ds:DigestMethod>
                                <ds:DigestValue>UTPSZoyMnEi0jKM1K13q9lWSuGNOyMiM6xAl8XR1SE9KNmf3/HSSlUniuLormjoiInWqhVbHLOI+wEz4C+QC/g==</ds:DigestValue>
                            </xades:CertDigest>
                            <xades:IssuerSerial>
                                <ds:X509IssuerName>CN=Let's Encrypt Authority X3, O=Let's Encrypt, C=US</ds:X509IssuerName>
                                <ds:X509SerialNumber>307228618548093469617232206275864271231086</ds:X509SerialNumber>
                            </xades:IssuerSerial>
                        </xades:Cert>
                    </xades:SigningCertificate>
                </xades:SignedSignatureProperties>
            </xades:SignedProperties>
        </xades:QualifyingProperties>
    </ds:Object>
</ds:Signature>
```

## Target Framework and Dependencies
* [.NET Standard 2.0](https://dotnet.microsoft.com/platform/dotnet-standard) - Target framework for this class library.
* [System.Security.Cryptography.Xml version 4.6.0](https://www.nuget.org/packages/System.Security.Cryptography.Xml/4.6.0) - Using SignedXml class to sign signature.
* [System.Security.Cryptography.Cng version 4.6.0](https://www.nuget.org/packages/System.Security.Cryptography.Cng/4.6.0) - Using .NET Cryptography Next-Generation.

## Usage examples

### To Sign digital signature
> ### Using certificate file
> If you have a certificate file in PKCS#12 format contains public key and private key in the same file (.pfx or .p12 file).
``` csharp
var cert = new X509Certificate2(File.ReadAllBytes("CERTIFICATE_FILE", "CERTIFICATE_PASSWORD"));

var xmlDoc = new XmlDocument();
xmlDoc.PreserveWhitespace = true;
xmlDoc.LoadXml(File.ReadAllText("XML_DOCUMENT_FILE"));

var signer = new XAdESSignature();
var result = signer.SignXml(cert, xmlDoc);

xmlDoc.DocumentElement.AppendChild(xmlDoc.ImportNode(result, true));
File.WriteAllText("XML_SIGNED_DOCUMENT_FILE", xmlDoc.OuterXml);
```
> ### Using certificate file and private key file
> If you have a certificate file in PKCS#12 that contains public key and identity only. Also you have a private key file in PEM format seperately.
> You must convert PEM to XML and save the private key to XML file first.
``` csharp
var cert = new X509Certificate2("CERTIFICATE_FILE");
var privateKey = File.ReadAllText("PRIVATE_KEY_FILE");

var xmlDoc = new XmlDocument();
xmlDoc.PreserveWhitespace = true;
xmlDoc.LoadXml(File.ReadAllText("XML_DOCUMENT_FILE"));

var signer = new XAdESSignature();
var result = signer.SignXml(cert, xmlDoc, privateKey);

xmlDoc.DocumentElement.AppendChild(xmlDoc.ImportNode(result, true));
File.WriteAllText("XML_SIGNED_DOCUMENT_FILE", xmlDoc.OuterXml);
```
> ### Using certificate in HSM
> If you have a certificate in PKCS#11 format that installed in your HSM.
> You must connect to a specific certificate / key in your HSM before signing.
``` csharp
X509Certificate2 cert = null;
var factories = new Pkcs11InteropFactories();
var pkcs11Library = new Pkcs11Library(factories, "CRYPTOKI_LIBRARY_FILE_INSTALLED_YOUR_SERVER", AppType.SignleThreaded);
var slots = pkcs11Library.GetSlotList(SlotsType.WithTokenPresent);
foreach (var slot in slots)
{
    using (var session = slot.OpenSession(SessionType.ReadOnly))
    {
        session.Login(CKU.CKU_USER, "PASSWORD_OF_HSM_USER");
        var keySearchTemplate = new List<IObjectAttribute>();
        keySearchTemplate.Add(new ObjectAttribute(CKA.CKA_CLASS, CKO,CKO_CERTIFICATE));
        keySearchTemplate.Add(new ObjectAttribute(CKA.CKA_TOKEN, true));
        keySearchTemplate.Add(new ObjectAttribute(CKA.CKA_CERTIFICATE_TYPE, CKC.CKC_X_509));
        keySearchTemplate.Add(new ObjectAttribute(CKA.CKA_LABEL, "X-KEY_NAME_IN_HSM"));
        
        var objectHandles = session.FindAllObjects(keySearchTemplate);
        foreach( var handle in objectHandles)
        {
            List<IObjectAttribute> objectAttributes = session.GetAttributeValue(handle, new List<CKA>() { CKA.CKA_ID, CKA.CKA_LABEL, CKA.CKA_VALUE });
            var ckaId = objectAttributes[0].GetValueAsByteArray();
            var ckaLabel = objectAttributes[1].GetValueAsString();
            var ckaValue = objectAttributes[2].GetValueAsByteArray();
            
            cert = new X509Certificate2(ckaValue);
        }
        session.Logout();
        
        if (cert != null)
        {
            break;
        }
    }
}

var provider = new CngProvider("PROVIDER_NAME_OF_HSM");
var existingKeyInHsm = CngKey.Open("KEY_NAME_IN_HSM", provider);
var asymmetricAlg = new RSACng(existingKeyInHsm);

var xmlDoc = new XmlDocument();
xmlDoc.PreserveWhitespace = true;
xmlDoc.LoadXml(File.ReadAllText("XML_DOCUMENT_FILE"));

var signer = new XAdESSignature();
var result = signer.SignXml(cert, xmlDoc, asymmetricAlg);

xmlDoc.DocumentElement.AppendChild(xmlDoc.ImportNode(result, true));
File.WriteAllText("XML_SIGNED_DOCUMENT_FILE", xmlDoc.OuterXml);
```

### To Verify digital signature
> If you want to verify your signed XML document, you can use VerifySignedXml method.
``` csharp
var signedXmlDoc = new XmlDocument();
signedXmlDoc.PreserveWhitespace = true;
signedXmlDoc.LoadXml(File.ReadAllText("XML_SIGNED_DOCUMENT_FILE"));

var result = signer.VerifySignedXml(cert, signedXmlDoc);
```

## References
* [XAdES wiki](https://en.wikipedia.org/wiki/XAdES) - What is XAdES?
* [XAdES W3C](https://www.w3.org/TR/XAdES/) - XAdES Specification
* [X509 wiki](https://en.wikipedia.org/wiki/X.509) - What is X509?
* [Signature Verification - 1](https://www.signatur.rtr.at/en/vd/Pruefung.html) - To verify signature of signed XML document
* [Signature Verification - 2](https://tools.chilkat.io/xmlDsigVerify.cshtml) - To verfiy signature of signed XML document
* [RSA Key Converter](https://superdry.apphb.com/tools/online-rsa-key-converter) - To convert PEM to XML and vice versa