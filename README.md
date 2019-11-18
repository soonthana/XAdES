# XAdES (XML Advanced Electronic Signatures) for .NET

This class library is for sign digital signatures to XML document in XAdES format which using Basic Electronic Signature profile only.

## Target Framework and Dependencies
* [.NET Standard 2.0](https://dotnet.microsoft.com/platform/dotnet-standard) - Target framework for this class library.
* [System.Security.Cryptography.Xml version 4.6.0](https://www.nuget.org/packages/System.Security.Cryptography.Xml/4.6.0) - Using SignedXml class to sign signature.
* [System.Security.Cryptography.Cng version 4.6.0](https://www.nuget.org/packages/System.Security.Cryptography.Cng/4.6.0) - Using .NET Cryptography Next-Generation.

## Usage examples

> ### Using certificate file
> dd
> ### Using certificate file and private key file
> dd
> ### Using certificate in HSM
> RECOMMENDED

## References
* [XAdES wiki](https://en.wikipedia.org/wiki/XAdES) - What is XAdES?
* [XAdES W3C](https://www.w3.org/TR/XAdES/) - XAdES Specification
* [X509 wiki](https://en.wikipedia.org/wiki/X.509) - What is X509?
* [Signature Verification - 1](https://www.signatur.rtr.at/en/vd/Pruefung.html) - To verify signature of signed XML document
* [Signature Verification - 2](https://tools.chilkat.io/xmlDsigVerify.cshtml) - To verfiy signature of signed XML document