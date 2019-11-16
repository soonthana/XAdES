using System;
using System.Globalization;
using System.Numerics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;

namespace XAdES
{
    public class XAdESSignature
    {
        #region Public properties
        public string UniqueId { get; set; }
        public string PrefixSignatureElement { get; set; }
        public string PrefixXadesElement { get; set; }
        #endregion

        #region Private fields
        private const string XmlDsigSignatureProperties = "http://uri.etsi.org/01903#SignedProperties";
        private const string XadesProofOfApproval = "http://uri.etsi.org/01903/v1.2.2#ProofOfApproval";
        private string XadesPrefix = "xades";
        private string SignaturePrefix = "ds";
        private const string SignatureNamespace = "http://www.w3.org/2000/09/xmldsig#";
        private const string XadesNamespace = "http://uri.etsi.org/01903/v1.3.2#";
        private string SignatureId = "Signature";
        private string SignaturePropertiesId = "SignedProperties";
        #endregion Private fields

        #region Contructor
        public XAdESSignature()
        {

        }

        public XAdESSignature(string prefixSignatureElement, string prefixXadesElement)
        {
            if (string.IsNullOrEmpty(prefixSignatureElement))
            {
                this.SignaturePrefix = null;
            }
            else
            {
                this.SignaturePrefix = prefixSignatureElement;
            }

            if (string.IsNullOrEmpty(prefixXadesElement))
            {
                this.XadesPrefix = null;
            }
            else
            {
                this.XadesPrefix = prefixXadesElement;
            }
        }

        public XAdESSignature(string uniqueId)
        {
            this.UniqueId = uniqueId;
            SignatureId = "xmldsig-" + this.UniqueId;
            SignaturePropertiesId = SignatureId + "-signedprops";
        }

        public XAdESSignature(string uniqueId, string prefixSignatureElement, string prefixXadesElement)
        {
            this.UniqueId = uniqueId;

            if (string.IsNullOrEmpty(prefixSignatureElement))
            {
                this.SignaturePrefix = null;
            }
            else
            {
                this.SignaturePrefix = prefixSignatureElement;
            }

            if (string.IsNullOrEmpty(prefixXadesElement))
            {
                this.XadesPrefix = null;
            }
            else
            {
                this.XadesPrefix = prefixXadesElement;
            }

            SignatureId = "xmldsig-" + this.UniqueId;
            SignaturePropertiesId = SignatureId + "-signedprops";
        }
        #endregion

        #region Public methods
        public XmlElement SignXml(X509Certificate2 certificate, XmlDocument document)
        {
            var signedXml = new SignedXml(document);
            signedXml.SigningKey = certificate.PrivateKey;

            return ComputeSignature(signedXml, certificate, document);
        }

        public XmlElement SignXml(X509Certificate2 certificate, XmlDocument document, string privateKey)
        {
            var signedXml = new SignedXml(document);
            RSA rsa = RSA.Create();
            rsa.fromXmlString(privateKey);
            signedXml.SigningKey = rsa;

            return ComputeSignature(signedXml, certificate, document);
        }

        public XmlElement SignXml(X509Certificate2 certificate, XmlDocument document, AsymmetricAlgorithm rsaAlg)
        {
            var signedXml = new SignedXml(document);
            signedXml.SigningKey = rsaAlg;

            return ComputeSignature(signedXml, certificate, document);
        }

        public string VerifySignedXml(X509Certificate2 certificate, XmlDocument document)
        {
            try
            {
                var signedXml = new SignedXml(document);

                if (string.IsNullOrEmpty(this.SignaturePrefix))
                {
                    var node = document.GetElementsByTagName("Signature")[0];
                    signedXml.LoadXml((XmlElement)node);
                }
                else
                {
                    var node = document.GetElementsByTagName(this.SignaturePrefix + ":" + "Signature")[0];
                    signedXml.LoadXml((XmlElement)node);
                }

                return signedXml.CheckSignature(certificate, true) == true ? "true" : "false-notvalid";
            }
            catch (Exception ex)
            {
                return "false-exception : " + ex.Message;
            }
        }
        #endregion

        #region Private methods
        private XmlElement ComputeSignature(SignedXml signedXml, X509Certificate2 certificate, XmlDocument document)
        {
            signedXml.SignedInfo.SignatureMethod = SignedXml.XmlDsigRSASHA512Url;
            signedXml.Signature.Id = $"{SignatureId}";

            var reference = new Reference { Uri = "", };
            reference.Id = "SignatureId-ref0";
            reference.DigestMethod = SignedXml.XmlDsigSHA512Url;
            reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
            signedXml.AddReference(reference);

            // 1st ComputeSignature for first <Reference><DigestValue> element - Digest message of XML data
            signedXml.ComputeSignature();

            // Keep the Digest message of XML data for first <Reference><DigestValue> element
            var signedInfoElementFirstComputeSignature = signedXml.Signature.SignedInfo.GetXml();
            var signedInfoReference1DigestValueElement = signedInfoElementFirstComputeSignature.GetElementsByTagName("DigestValue")[0].InnerText;

            // This is workaround for overcoming a bug in the library
            signedXml.SignedInfo.References.Clear();

            var objectNode = BuildNodeObject(document, certificate);

            var dataObject = new DataObject();
            dataObject.LoadXml(objectNode);
            signedXml.AddObject(dataObject);

            var parametersSignature = new Reference
            {
                Uri = $"#{SignaturePropertiesId}",
                Type = "http://uri.etsi.org/01903#SignedProperties",
                DigestMethod = SignedXml.XmlDsigSHA512Url
            };
            signedXml.AddReference(parametersSignature);

            // 2nd ComputeSignature for second <Reference><DigestValue> element - Digest message of Signed Properties
            signedXml.ComputeSignature();

            // Keep the Digest message of Signed Properties for second <Reference><DigestValue> element
            var signedInfoElementSecondComputeSignature = signedXml.Signature.SignedInfo.GetXml();
            var signedInfoReference2DigestValueElement = signedInfoElementSecondComputeSignature.GetElementsByTagName("DigestValue")[0].InnerText;

            // Build up <SignedInfo> element with 2 <Reference> elements
            var signedInfoNode = BuildNodeSignedInfo(document, signedInfoReference1DigestValueElement, signedInfoReference2DigestValueElement);

            // Build up <Signature> element with all child elements
            var signatureNode = BuildNodeSignature(document);
            var signatureValueNode = BuildNodeSignatureValue(document);
            var keyInfoNode = BuildNodeKeyInfo(document, certificate);
            signatureNode.AppendChild(signedInfoNode);
            signatureNode.AppendChild(signatureValueNode);
            signatureNode.AppendChild(keyInfoNode);
            signatureNode.AppendChild(objectNode);

            // Load modified <Signature> back to SignedXml's object
            signedXml.LoadXml(signatureNode);

            // This is workaround for overcoming a bug in the library
            signedXml.SignedInfo.References.Clear();

            // 3rd ComputeSignature for <SignatureValue> element - Signature of XML data with XAdES
            signedXml.ComputeSignature();

            // Get new Signature value and Replacing <SignagureValue>
            string recomputedSignatureValue = Convert.ToBase64String(signedXml.SignatureValue);
            ReplaceSignatureValue(signatureNode, recomputedSignatureValue);

            return signatureNode;
        }

        private XmlElement BuildNodeSignature(XmlDocument document)
        {
            // <Signature>
            var signatureNode = document.CreateElement(SignaturePrefix, "Signature", SignatureNamespace);
            var signatureIdAttribute = document.CreateAttribute("Id");
            signatureIdAttribute.InnerText = SignatureId;
            signatureNode.Attributes.Append(signatureIdAttribute);
            document.DocumentElement.AppendChild(signatureNode);

            return (XmlElement)document.SelectSingleNode("//*[local-name()='Signature']");
        }

        private XmlElement BuildNodeObject(XmlDocument document, X509Certificate2 certificate)
        {
            // <Signature><Object>
            var objectNode = document.CreateElement(SignaturePrefix, "Object", SignatureNamespace);
            document.DocumentElement.AppendChild(objectNode);

            // <Signature><Object><QualifyingProperties>
            var qualifyingPropertiesNode = document.CreateElement(XadesPrefix, "QualifyingProperties", XadesNamespace);
            var qualifyingPropertiesAttrTarget = document.CreateAttribute("Target");
            var qualifyingPropertiesAttrXAdES141 = document.CreateAttribute("xmlns:xades141");
            qualifyingPropertiesAttrTarget.Value = $"#{SignatureId}";
            qualifyingPropertiesAttrXAdES141.Value = "http://uri.etsi.org/01903/v1.4.1#";
            qualifyingPropertiesNode.Attributes.Append(qualifyingPropertiesAttrTarget);
            qualifyingPropertiesNode.Attributes.Append(qualifyingPropertiesAttrXAdES141);
            objectNode.AppendChild(qualifyingPropertiesNode);

            // <Signature><Object><QualifyingProperties><SignedProperties>
            var signedPropertiesNode = document.CreateElement(XadesPrefix, "SignedProperties", XadesNamespace);
            var signedPropertiesAttrId = document.CreateAttribute("Id");
            signedPropertiesAttrId.Value = $"{SignaturePropertiesId}";
            signedPropertiesNode.Attributes.Append(signedPropertiesAttrId);
            qualifyingPropertiesNode.AppendChild(signedPropertiesNode);

            // <Signature><Object><QualifyingProperties><SignedProperties><SignedSignatureProperties>
            var signedSignaturePropertiesNode = document.CreateElement(XadesPrefix, "SignedSignatureProperties", XadesNamespace);
            signedPropertiesNode.AppendChild(signedSignaturePropertiesNode);

            // <Signature><Object><QualifyingProperties><SignedProperties><SignedSignatureProperties><SigningTime>
            var signingTimeNode = document.CreateElement(XadesPrefix, "SigningTime", XadesNamespace);
            //signingTime.InnerText = $"{DateTime.UtcNow.ToString("s")}Z";
            signingTimeNode.InnerText = $"2019-11-05T17:00:00Z";
            signedSignaturePropertiesNode.AppendChild(signingTimeNode);

            // <Signature><Object><QualifyingProperties><SignedProperties><SignedSignatureProperties><SigningCertificate>
            var signingCertificateNode = document.CreateElement(XadesPrefix, "SigningCertificate", XadesNamespace);
            signedSignaturePropertiesNode.AppendChild(signingCertificateNode);

            // <Signature><Object><QualifyingProperties><SignedProperties><SignedSignatureProperties><SigningCertificate><Cert>
            var certNode = document.CreateElement(XadesPrefix, "Cert", XadesNamespace);
            signingCertificateNode.AppendChild(certNode);

            // <Signature><Object><QualifyingProperties><SignedProperties><SignedSignatureProperties><SigningCertificate><Cert><CertDigest>
            var certDigestNode = document.CreateElement(XadesPrefix, "CertDigest", XadesNamespace);
            certNode.AppendChild(certDigestNode);

            // <Signature><Object><QualifyingProperties><SignedProperties><SignedSignatureProperties><SigningCertificate><Cert><CertDigest><DigestMethod>
            var digestMethodNode = document.CreateElement(SignaturePrefix, "DigestMethod", SignatureNamespace);
            var digestMethodAttrAlgorithm = document.CreateAttribute("Algorithm");
            digestMethodAttrAlgorithm.Value = SignedXml.XmlDsigSHA512Url;
            digestMethodNode.Attributes.Append(digestMethodAttrAlgorithm);
            digestMethodNode.InnerText = "";
            certDigestNode.AppendChild(digestMethodNode);

            // <Signature><Object><QualifyingProperties><SignedProperties><SignedSignatureProperties><SigningCertificate><Cert><CertDigest><DigestValue>
            var digestValueNode = document.CreateElement(SignaturePrefix, "DigestValue", SignatureNamespace);
            digestValueNode.InnerText = Convert.ToBase64String(certificate.GetCertHash());
            certDigestNode.AppendChild(digestValueNode);

            // <Signature><Object><QualifyingProperties><SignedProperties><SignedSignatureProperties><SigningCertificate><Cert><IssuerSerial>
            var issuerSerialNode = document.CreateElement(XadesPrefix, "IssuerSerial", XadesNamespace);
            certNode.AppendChild(issuerSerialNode);

            // <Signature><Object><QualifyingProperties><SignedProperties><SignedSignatureProperties><SigningCertificate><Cert><IssuerSerial><X509IssuerName>
            var x509IssuerNameNode = document.CreateElement(SignaturePrefix, "X509IssuerName", SignatureNamespace);
            x509IssuerNameNode.InnerText = certificate.Issuer;
            issuerSerialNode.AppendChild(x509IssuerNameNode);

            // <Signature><Object><QualifyingProperties><SignedProperties><SignedSignatureProperties><SigningCertificate><Cert><IssuerSerial><X509SerialNumber>
            var x509SerialNumberNode = document.CreateElement(SignaturePrefix, "X509SerialNumber", SignatureNamespace);
            x509SerialNumberNode.InnerText = ToDecimalString(certificate.SerialNumber);
            issuerSerialNode.AppendChild(x509SerialNumberNode);

            return (XmlElement)document.SelectSingleNode("//*[local-name()='Object']");
        }

        private XmlElement BuildNodeSignedInfo(XmlDocument document, string reference1DigestValue, string reference2DigestValue)
        {
            // <Signature><SignedInfo>
            var signedInfoNode = document.CreateElement(SignaturePrefix, "SignedInfo", SignatureNamespace);
            document.DocumentElement.AppendChild(signedInfoNode);

            // <Signature><SignedInfo><CanonicalizationMethod>
            var canonicalizationMethodNode = document.CreateElement(SignaturePrefix, "CanonicalizationMethod", SignatureNamespace);
            var canonicalizationMethodAttr = document.CreateAttribute("Algorithm");
            canonicalizationMethodAttr.Value = SignedXml.XmlDsigC14NTransformUrl;
            canonicalizationMethodNode.Attributes.Append(canonicalizationMethodAttr);
            signedInfoNode.AppendChild(canonicalizationMethodNode);

            // <Signature><SignedInfo><SignatureMethod>
            var signatureMethodNode = document.CreateElement(SignaturePrefix, "SignatureMethod", SignatureNamespace);
            var signatureMethodAttr = document.CreateAttribute("Algorithm");
            signatureMethodAttr.Value = SignedXml.XmlDsigRSASHA512Url;
            signatureMethodNode.Attributes.Append(signatureMethodAttr);
            signedInfoNode.AppendChild(signatureMethodNode);

            // <Signature><SignedInfo><Reference>
            var reference1Node = document.CreateElement(SignaturePrefix, "Reference", SignatureNamespace);
            var reference1AttrId = document.CreateAttribute("Id");
            var reference1AttrURI = document.CreateAttribute("URI");
            reference1AttrId.Value = $"{SignatureId}-ref0";
            reference1AttrURI.Value = "";
            reference1Node.Attributes.Append(reference1AttrId);
            reference1Node.Attributes.Append(reference1AttrURI);
            signedInfoNode.AppendChild(reference1Node);

            // <Signature><SignedInfo><Reference><Transforms>
            var transforms1Node = document.CreateElement(SignaturePrefix, "Transforms", SignatureNamespace);
            reference1Node.AppendChild(transforms1Node);

            // <Signature><SignedInfo><Reference><Transforms><Tranform>
            var transform1Node = document.CreateElement(SignaturePrefix, "Transform", SignatureNamespace);
            var transform1Attr = document.CreateAttribute("Algorithm");
            transform1Attr.Value = SignedXml.XmlDsigEnvelopedSignatureTransformUrl;
            transform1Node.Attributes.Append(transform1Attr);
            transforms1Node.AppendChild(transform1Node);

            // <Signature><SignedInfo><Reference><DigestMethod>
            var digestMethod1Node = document.CreateElement(SignaturePrefix, "DigestMethod", SignatureNamespace);
            var digestMethod1Attr = document.CreateAttribute("Algorithm");
            digestMethod1Attr.Value = SignedXml.XmlDsigSHA512Url;
            digestMethod1Node.Attributes.Append(digestMethod1Attr);
            reference1Node.AppendChild(digestMethod1Node);

            // <Signature><SignedInfo><Reference><DigestValue>
            var digestValue1Node = document.CreateElement(SignaturePrefix, "DigestValue", SignatureNamespace);
            digestValue1Node.InnerText = reference1DigestValue;
            reference1Node.AppendChild(digestValue1Node);

            // <Signature><SignedInfo><Reference>
            var reference2Node = document.CreateElement(SignaturePrefix, "Reference", SignatureNamespace);
            var reference2AttrType = document.CreateAttribute("Type");
            var reference2AttrURI = document.CreateAttribute("URI");
            reference2AttrType.Value = XmlDsigSignatureProperties;
            reference2AttrURI.Value = $"#{SignaturePropertiesId}";
            reference2Node.Attributes.Append(reference2AttrType);
            reference2Node.Attributes.Append(reference2AttrURI);
            signedInfoNode.AppendChild(reference2Node);

            // <Signature><SignedInfo><Reference><DigestMethod>
            var digestMethod2Node = document.CreateElement(SignaturePrefix, "DigestMethod", SignatureNamespace);
            var digestMethod2Attr = document.CreateAttribute("Algorithm");
            digestMethod2Attr.Value = SignedXml.XmlDsigSHA512Url;
            digestMethod2Node.Attributes.Append(digestMethod2Attr);
            digestMethod2Node.InnerText = "";
            reference2Node.AppendChild(digestMethod2Node);

            // <Signature><SignedInfo><Reference><DigestValue>
            var digestValue2Node = document.CreateElement(SignaturePrefix, "DigestValue", SignatureNamespace);
            digestValue2Node.InnerText = reference2DigestValue;
            reference2Node.AppendChild(digestValue2Node);

            return (XmlElement)document.SelectSingleNode("//*[local-name()='SignedInfo']");
        }

        private XmlElement BuildNodeSignatureValue(XmlDocument document)
        {
            // <Signature><SignatureValue>
            var signatureValueNode = document.CreateElement(SignaturePrefix, "SignatureValue", SignatureNamespace);
            var signatureValueAttrId = document.CreateAttribute("Id");
            signatureValueAttrId.Value = $"{SignatureId}-sigvalue";
            signatureValueNode.InnerText = "";
            signatureValueNode.Attributes.Append(signatureValueAttrId);
            document.DocumentElement.AppendChild(signatureValueNode);

            return (XmlElement)document.SelectSingleNode("//*[local-name()='SignatureValue']");
        }

        private XmlElement BuildNodeKeyInfo(XmlDocument document, X509Certificate2 certificate)
        {
            // <Signature><KeyInfo>
            var keyInfoNode = document.CreateElement(SignaturePrefix, "KeyInfo", SignatureNamespace);
            document.DocumentElement.AppendChild(keyInfoNode);

            // <Signature><KeyInfo><X509Data>
            var x509Node = document.CreateElement(SignaturePrefix, "X509Data", SignatureNamespace);
            keyInfoNode.AppendChild(x509Node);

            // <Signature><KeyInfo><X509Data><X509Certificate>
            var x509CertificateNode = document.CreateElement(SignaturePrefix, "X509Certificate", SignatureNamespace);
            x509CertificateNode.InnerText = Convert.ToBase64String(certificate.GetRawCertData());
            x509Node.AppendChild(x509CertificateNode);

            return (XmlElement)document.SelectSingleNode("//*[local-name()='KeyInfo']");
        }

        private string ToDecimalString(string serialNumber)
        {
            BigInteger bi;

            if (BigInteger.TryParse(serialNumber, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out bi))
            {
                return bi.ToString(CultureInfo.InvariantCulture);
            }
            else
            {
                return serialNumber;
            }
        }

        // https://stackoverflow.com/questions/30579938/generate-digital-signature-but-with-a-specific-namespace-prefix-ds
        private void ReplaceSignatureValue(XmlElement signature, string newValue)
        {
            if (signature == null) throw new ArgumentNullException(nameof(signature));
            if (signature.OwnerDocument == null) throw new ArgumentException("No owner document", nameof(signature));

            if (string.IsNullOrEmpty(this.SignaturePrefix))
            {
                XmlNode signatureValue = signature.SelectSingleNode("//*[local-name()='SignatureValue']");
                if (signatureValue == null)
                    throw new Exception("Signature does not contain 'SignatureValue'");

                signatureValue.InnerXml = newValue;
            }
            else
            {
                XmlNamespaceManager nsm = new XmlNamespaceManager(signature.OwnerDocument.NameTable);
                nsm.AddNamespace(this.SignaturePrefix, SignedXml.XmlDsigNamespaceUrl);

                XmlNode signatureValue = signature.SelectSingleNode(this.SignaturePrefix + ":" + "SignatureValue", nsm);
                if (signatureValue == null)
                    throw new Exception("Signature does not contain '" + this.SignaturePrefix + ":" + "SignatureValue'");

                signatureValue.InnerXml = newValue;
            }
        }
        #endregion
    }
}
