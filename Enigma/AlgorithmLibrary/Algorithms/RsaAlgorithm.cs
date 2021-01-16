using System;
using System.Linq;
using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace Enigma.AlgorithmLibrary.Algorithms
{
    /// <summary>
    /// Wrapper for the .NET RSACryptoServiceProvider class and the RSA algorithm.
    /// </summary>
    public class RsaAlgorithm : IAsymmetricAlgorithm
    {
        /// <summary>
        /// Represents the name of the asymmetric algorithm.
        /// </summary>
        public static readonly string NameSignature = "RSA";

        /// <summary>
        /// Represents the public/private key for the asymmetric algorithm. RSA wrapper <see cref="RsaAlgorithm"/> allows 2048-, 3072- and 4096-bit key sizes.
        /// </summary>
        public RSAParameters Key { get; set; }

        /// <summary>
        /// Initializes a new instance of the <see cref="RsaAlgorithm"/> class with the specified public/private key.
        /// </summary>
        /// <param name="rsaKeyParams">Private or public RSA key.</param>
        public RsaAlgorithm(RSAParameters rsaKeyParams)
        {
            Key = rsaKeyParams;
        }

        /// <summary>
        /// Compares public RSA key with a private RSA key by encrypting/decrypting random 16 bytes of data.
        /// This method is slower than <see cref="CompareKeys(RSAParameters, RSAParameters)"/> method.
        /// </summary>
        /// <returns>true if the keys match, otherwise false.</returns>
        public static bool AreKeysMatched(RSAParameters publicKey, RSAParameters privateKey)
        {
            var data = new byte[16];
            new RNGCryptoServiceProvider().GetBytes(data);

            using var decryptRSA = new RSACryptoServiceProvider();
            using var encryptRSA = new RSACryptoServiceProvider();

            encryptRSA.ImportParameters(publicKey);
            decryptRSA.ImportParameters(privateKey);

            var decrypted = decryptRSA.Decrypt(encryptRSA.Encrypt(data, false), false);

            return data.SequenceEqual(decrypted);
        }

        /// <summary>
        /// Compares public RSA key extracted from <see cref="System.Security.Cryptography.X509Certificates"/> certificate with a public key extracted from a private RSA key.
        /// This method is faster than <see cref="AreKeysMatched(RSAParameters, RSAParameters)"/> method.
        /// </summary>
        /// <returns>true if the keys match, otherwise false.</returns>
        public static bool CompareKeys(RSAParameters publicKey, RSAParameters privateKey)
        {
            return publicKey.Modulus.SequenceEqual(privateKey.Modulus) && publicKey.Exponent.SequenceEqual(privateKey.Exponent);
        }

        /// <summary>
        /// Compares public RSA key extracted from <see cref="System.Security.Cryptography.X509Certificates"/> certificate with a public key extracted from a private RSA key.
        /// This method is slower than <see cref="CompareKeys(RSAParameters, RSAParameters)"/> method.
        /// </summary>
        /// <returns>true if the keys match, otherwise false.</returns>
        [ObsoleteAttribute("This method is obsolete. Call CompareKeys instead.", true)]
        public static bool AreKeysMatched2(RSAParameters publicKey, RSAParameters privateKey)
        {
            var pemObject1 = DotNetUtilities.GetRsaPublicKey(publicKey);
            var rsaParams1 = DotNetUtilities.ToRSAParameters((RsaKeyParameters)pemObject1);

            var pemObject2 = DotNetUtilities.GetRsaKeyPair(privateKey);
            var rsaParams2 = DotNetUtilities.ToRSAParameters((RsaKeyParameters)pemObject2.Public);

            return ByteArrayCompare(rsaParams1.Modulus, rsaParams2.Modulus) && ByteArrayCompare(rsaParams1.Exponent, rsaParams2.Exponent);
        }

        /// <summary>
        /// Helper method for <see cref="AreKeysMatched2(RSAParameters, RSAParameters)"/> obsolete method.
        /// <returns>true if arrays mathch; false if arrays don't match.</returns>
        [Obsolete("Only used in a deprecated method AreKeysMatched2")]
        private static bool ByteArrayCompare(ReadOnlySpan<byte> array1, ReadOnlySpan<byte> array2)
        {
            return array1.SequenceEqual(array2);
        }

        public byte[] Encrypt(byte[] data)
        {
            byte[] encryptedData;

            using var rsaProvider = new RSACryptoServiceProvider();

            rsaProvider.ImportParameters(Key);
            encryptedData = rsaProvider.Encrypt(data, false);

            return encryptedData;
        }

        public byte[] Decrypt(byte[] data)
        {
            byte[] decryptedData;

            var rsaProvider = new RSACryptoServiceProvider();
            rsaProvider.ImportParameters(Key);
            decryptedData = rsaProvider.Decrypt(data, false);

            return decryptedData;
        }

        public byte[] CreateSignature(byte[] data, HashAlgorithm hashAlgo)
        {
            using var rsaProvider = new RSACryptoServiceProvider();

            rsaProvider.ImportParameters(Key);
            return rsaProvider.SignData(data, hashAlgo);
        }

        public bool VerifySignature(byte[] data, HashAlgorithm hasher, byte[] signature)
        {
            using var rsaProvider = new RSACryptoServiceProvider();

            rsaProvider.ImportParameters(Key);
            return rsaProvider.VerifyData(data, hasher, signature);
        }

        public string GetAlgorithmNameSignature()
        {
            return NameSignature;
        }
    }
}
