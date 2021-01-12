using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

namespace Enigma.Models
{
    public static class CertificateValidator
    {
        /// <summary>
        /// Checks if the certificate has expired and it also checks if it is issued by a proper root certificate if the <paramref name="checkRoot"/> is set to true.
        /// </summary>
        /// <param name="certificateToValidate">Certificate that is checked.</param>
        /// <param name="error">String describing error.</param>
        /// <param name="checkRoot">If set to <see cref="true"/> true, <see cref="VerifyCertificate(X509Certificate2, out string, bool)"/>  will check if certificate is issued by a proper root certificate. </param>
        /// <returns>true if the certificate hasn't expired and if it issued by a proper root certificate, otherwise returns false.</returns>
        public static bool VerifyCertificate(X509Certificate2 certificateToValidate, out string error, bool checkRoot)
        {
            // root certificate that this application trusts
            var authority = new X509Certificate2(@"C:\Users\Aleksa\source\repos\Enigma\OPENSSL\ca.pem");
            error = null;

            using var chain = new X509Chain();
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            chain.ChainPolicy.RevocationFlag = X509RevocationFlag.EndCertificateOnly;
            chain.ChainPolicy.VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority;
            chain.ChainPolicy.VerificationTime = DateTime.Now;
            chain.ChainPolicy.ExtraStore.Add(authority);

            var isChainValid = chain.Build(certificateToValidate);

            if (!isChainValid)
            {
                error = "Certificate has expired.";
                return false;
            }
            else if (!checkRoot)
            {
                return true;
            }
            else // if checkRoot == true
            {
                // verify if client certificate is signed by proper root
                var isChainIssuedByRoot = chain.ChainElements.Cast<X509ChainElement>().Any(x => x.Certificate.Thumbprint == authority.Thumbprint);

                if (!isChainIssuedByRoot)
                {
                    error = "Certificate isn't signed by a proper root CA.";
                    return false;
                }

                return true;
            }
        }

        /// <summary>
        /// Checks if key size is equal or greater than 2048 bits.
        /// </summary>
        /// <param name="certificateToValidate">Certificate that is checked.</param>
        /// <returns>true if the key is equal or greater than 2048 bits, otherwise returns false.</returns>
        public static bool VerifyCertificateKeyLength(X509Certificate2 certificateToValidate)
        {
            //Since 2015, NIST recommends a minimum of 2048 - bit keys for RSA, an update to the widely - accepted recommendation of a 1024 - bit minimum since at least 2002.
            return certificateToValidate.PublicKey.Key.KeySize >= 2048;
        }

        /// <summary>
        /// Check if certificate has been revoked.
        /// </summary>
        /// <param name="certificateToValidate"> Certificate that is checked.</param>
        /// <returns>true if certificate has been revoked, otherwise returns false.</returns>
        public static bool VerifyCertificateRevocationStatus(X509Certificate2 certificateToValidate)
        {
            try
            {
                var buffer = File.ReadAllBytes(@"C:\Users\Aleksa\source\repos\Enigma\OPENSSL\crl\list.crl");
                var crlParser = new X509CrlParser();
                var crl = crlParser.ReadCrl(buffer);

                return crl.IsRevoked(DotNetUtilities.FromX509Certificate(certificateToValidate));
            }
            catch (Exception)
            {
                return false;
            }
        }

        /// <summary>
        /// Check if certificate key usage is set to <see cref="X509KeyUsageFlags.DigitalSignature"/> and <see cref="X509KeyUsageFlags.KeyEncipherment"/>.
        /// </summary>
        /// <param name="certificateToValidate"> Certificate that is checked.</param>
        /// <returns>true if the key usage is set to <see cref="X509KeyUsageFlags.DigitalSignature"/> and <see cref="X509KeyUsageFlags.KeyEncipherment"/>, otherwise returns false.</returns>
        public static bool VerifyKeyUsage(X509Certificate2 certificateToValidate)
        {
            var extensions = certificateToValidate.Extensions.OfType<X509KeyUsageExtension>().ToList();
            if (!extensions.Any())
            {
                return certificateToValidate.Version < 3;
            }

            var keyUsageFlags = extensions.Select(ext => ext.KeyUsages).ToList()[0];
            return keyUsageFlags.HasFlag(X509KeyUsageFlags.DigitalSignature) && keyUsageFlags.HasFlag(X509KeyUsageFlags.KeyEncipherment);
        }
    }
}
