using System;
using System.IO;
using System.Linq;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.Security;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;

namespace Enigma
{
    public static class CertificateValidator
    {
        public static bool VerifyCertificate(X509Certificate2 certificateToValidate)
        {
            X509Certificate2 authority = new X509Certificate2(/*ROOT CA location*/);

            using X509Chain chain = new X509Chain();
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            chain.ChainPolicy.RevocationFlag = X509RevocationFlag.EndCertificateOnly;
            chain.ChainPolicy.VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority;
            chain.ChainPolicy.VerificationTime = DateTime.Now;
            chain.ChainPolicy.ExtraStore.Add(authority);

            bool isChainValid = chain.Build(certificateToValidate);

            if (!isChainValid)
            {
                return false;
            }

            // verify if client certificate is signed by proper root
            var isChainIssuedByRoot = chain.ChainElements.Cast<X509ChainElement>().All(x => x.Certificate.Thumbprint == authority.Thumbprint); // or Any insted of All

            if (!isChainIssuedByRoot)
            {
                return false;
            }


            // check if the certificate key has the righth key usage properties - only for Version > 2
            List<X509KeyUsageExtension> extensions = certificateToValidate.Extensions.OfType<X509KeyUsageExtension>().ToList();
            if (!extensions.Any())
            {
                foreach (var extension in extensions)
                {
                    return extension.KeyUsages == X509KeyUsageFlags.DigitalSignature || extension.KeyUsages == X509KeyUsageFlags.KeyEncipherment || extension.KeyUsages == X509KeyUsageFlags.DataEncipherment;
                }
            }
            else
            {
                return false;
            }

            // check if certifacate has been revoked
            try
            {
                byte[] buffer = File.ReadAllBytes(/*CRL List path*/);
                X509CrlParser crlParser = new X509CrlParser();
                X509Crl crl = crlParser.ReadCrl(buffer);

                return crl.IsRevoked(DotNetUtilities.FromX509Certificate(certificateToValidate));
            }
            catch (Exception)
            {
            }

            return true;
        }

        public static bool VerifyKeyUsage(X509Certificate2 cert)
        {
            List<X509KeyUsageExtension> extensions = cert.Extensions.OfType<X509KeyUsageExtension>().ToList();
            if (!extensions.Any())
            {
                return cert.Version < 3;
            }

            List<X509KeyUsageFlags> keyUsageFlags = extensions.Select((ext) => ext.KeyUsages).ToList();
            return keyUsageFlags.Contains(X509KeyUsageFlags.KeyEncipherment) && keyUsageFlags.Contains(X509KeyUsageFlags.DigitalSignature);
        }
    }
}
