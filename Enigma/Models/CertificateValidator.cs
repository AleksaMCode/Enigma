using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

namespace Enigma.Models
{
    /// <summary>
    /// Validator for <see cref="X509Certificate2"/> user public certificates.
    /// </summary>
    public static class CertificateValidator
    {
        /// <summary>
        /// Checks if the certificate has expired and it also checks if it is issued by a proper root certificate if the <paramref name="checkRoot"/> is set to true.
        /// </summary>
        /// <param name="certificateToValidate">Certificate that is checked.</param>
        /// <param name="caTrustListPath">Path on FS to CA trust list.</param>
        /// <param name="error">String describing error.</param>
        /// <param name="checkRoot">If set to <see cref="true"/> true, <see cref="VerifyCertificate(X509Certificate2, out string, bool)"/>  will check if certificate is issued by a proper root certificate. </param>
        /// <returns>true if the certificate hasn't expired and if it issued by a proper root certificate, otherwise false.</returns>
        public static bool VerifyCertificate(X509Certificate2 certificateToValidate, string caTrustListPath, out string error, bool checkRoot)
        {
            // root certificate that this application trusts
            var authority = new X509Certificate2(caTrustListPath);

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
        /// <returns>true if the key is equal or greater than 2048 bits, otherwise false.</returns>
        public static bool VerifyCertificateKeyLength(X509Certificate2 certificateToValidate)
        {
            // Since 2015, NIST recommends a minimum of 2048 bit keys for RSA, an update to the widely accepted recommendation of a 1024 bit minimum since at least 2002.
            return certificateToValidate.PublicKey.Key.KeySize >= 2048;
        }

        /// <summary>
        /// Checks if certificate has been revoked.
        /// </summary>
        /// <param name="certificateToValidate">Certificate that is checked.</param>
        /// <param name="crlListPath">Path on FS to CRL directory.</param>
        /// <param name="caTrustListPath">Path on FS to CA trust list.</param>
        /// <returns>true if certificate has been revoked, otherwise false.</returns>
        public static bool VerifyCertificateRevocationStatus(X509Certificate2 certificateToValidate, string crlListPath, string caTrustListPath)
        {
            var dir = new DirectoryInfo(crlListPath);
            FileInfo[] crlList = null;

            try
            {
                crlList = dir.GetFiles("*.crl");
            }
            catch (Exception ex)
            {
                if (ex is DirectoryNotFoundException || ex is ArgumentNullException)
                {
                    throw new Exception("User certificate validation failed. CRL file is missing.");
                }
            }

            foreach (var crlRaw in crlList)
            {
                var buffer = File.ReadAllBytes(crlListPath + "\\" + crlRaw.Name);
                var crlParser = new X509CrlParser();
                var crl = crlParser.ReadCrl(buffer);

                try
                {
                    var rootCa = new X509Certificate2(caTrustListPath);
                    var publicKey = ((RSACryptoServiceProvider)rootCa.PublicKey.Key).ExportParameters(false);

                    // Check if the crl is issued by a proper root CA.
                    crl.Verify(DotNetUtilities.GetRsaPublicKey(publicKey));
                }
                catch (Exception)
                {
                    throw new Exception("User certificate validation failed. CRL isn't issued by a proper root CA.");
                }

                var revokeStatus = crl.IsRevoked(DotNetUtilities.FromX509Certificate(certificateToValidate));
                if (revokeStatus == false)
                {
                    return false;
                }
            }

            return true;
        }

        /// <summary>
        /// Checks if certificate key usage is set to <see cref="X509KeyUsageFlags.DigitalSignature"/> and <see cref="X509KeyUsageFlags.KeyEncipherment"/>.
        /// </summary>
        /// <param name="certificateToValidate">Certificate that is checked.</param>
        /// <returns>true if the key usage is set to <see cref="X509KeyUsageFlags.DigitalSignature"/> and <see cref="X509KeyUsageFlags.KeyEncipherment"/>, otherwise false.</returns>
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
