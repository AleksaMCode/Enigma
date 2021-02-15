using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.OpenSsl;
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
        /// Import OpenSSH PEM public RSA key <see cref="string"/> into RSAParameters.
        /// <param name="publicKeyInPem">User public RSA key in PEM format.</param>
        /// <returns>Importet RSA public key.</returns>
        /// </summary>
        public static RSAParameters ImportPublicKey(string publicKeyInPem)
        {
            var pr = new PemReader(new StringReader(publicKeyInPem));
            var publicKey = (AsymmetricKeyParameter)pr.ReadObject();

            return DotNetUtilities.ToRSAParameters((RsaKeyParameters)publicKey);
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
        /// Compares two public RSA keys or public with private RSA key.
        /// When comparing private and public keys, this method is faster than <see cref="AreKeysMatched(RSAParameters, RSAParameters)"/> method.
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

        /// <summary>
        /// Encrypts data using RSA asymmetric encryption.
        /// </summary>
        /// <param name="data">Input data (opentext) used for encryption.</param>
        /// <returns>Encrypted data.</returns>
        public byte[] Encrypt(byte[] data)
        {
            byte[] encryptedData;

            using var rsaProvider = new RSACryptoServiceProvider();

            rsaProvider.ImportParameters(Key);
            encryptedData = rsaProvider.Encrypt(data, false);

            return encryptedData;
        }

        /// <summary>
        /// Decrypts data using RSA asymmetric encryption.
        /// </summary>
        /// <param name="data">Encrypted data (ciphertext) used for decryption.</param>
        /// <returns>Decrypted data.</returns>
        public byte[] Decrypt(byte[] data)
        {
            byte[] decryptedData;

            var rsaProvider = new RSACryptoServiceProvider();
            rsaProvider.ImportParameters(Key);
            decryptedData = rsaProvider.Decrypt(data, false);

            return decryptedData;
        }

        /// <summary>
        /// Computes the hash value of the specified byte array using the specified hash
        /// algorithm (<see cref="MD5"/>, <see cref="SHA1"/>, <see cref="SHA256"/>, <see cref="SHA384"/> or <see cref="SHA512"/>) and signs the resulting hash value.
        /// </summary>
        /// <param name="data">The input data for which to compute the hash.</param>
        /// <param name="hashAlgo">The hash algorithm to use to create the hash value.</param>
        /// <returns>The <see cref="System.Security.Cryptography.RSA"></see> signature for the specified data.</returns>
        public byte[] CreateSignature(byte[] data, HashAlgorithm hashAlgo)
        {
            using var rsaProvider = new RSACryptoServiceProvider();

            rsaProvider.ImportParameters(Key);
            return rsaProvider.SignData(data, hashAlgo);
        }

        /// <summary>
        /// Computes the hash value of the specified byte array using the specified hash
        /// algorithm (MD2, MD4, RIPEMD-128, RIPEMD-160 or RIPEMD-256) and signs the resulting hash value.
        /// </summary>
        /// <param name="data">The input data for which to compute the hash.</param>
        /// <param name="hashAlgo">The hash algorithm to use to create the hash value.</param>
        /// <returns>The RSA signature for the specified data created using <see cref="Org.BouncyCastle"/> library.</returns>
        public byte[] CreateSignature(byte[] data, ISigner hashAlgo)
        {
            // Convert .NETs RSAParameters to Bouncy Castles RsaKeyParameters
            var key = new RsaKeyParameters(true, new BigInteger(Key.Modulus), new BigInteger(Key.Exponent));

            hashAlgo.Init(true, key);
            hashAlgo.BlockUpdate(data, 0, data.Length);

            return hashAlgo.GenerateSignature();
        }

        /// <summary>
        /// Verifies that a digital signature is valid by determining the hash value in the
        /// signature using the provided public key and comparing it to the hash value of
        /// the provided data.
        /// </summary>
        /// <param name="data">The data that was signed.</param>
        /// <param name="hashAlgo">The name of the hash algorithm used to create the hash value of the data.</param>
        /// <param name="signature">The signature data to be verified.</param>
        /// <returns>true if the signature is valid, otherwise false.</returns>
        public bool VerifySignature(byte[] data, HashAlgorithm hashAlgo, byte[] signature)
        {
            using var rsaProvider = new RSACryptoServiceProvider();

            rsaProvider.ImportParameters(Key);
            return rsaProvider.VerifyData(data, hashAlgo, signature);
        }

        /// <summary>
        /// Verifies that a digital signature is valid by determining the hash value in the
        /// signature using the provided public key and comparing it to the hash value of
        /// the provided data.
        /// </summary>
        /// <param name="data">The data that was signed.</param>
        /// <param name="hashAlgo">The name of the hash algorithm used to create the hash value of the data.</param>
        /// <param name="signature">The signature data to be verified.</param>
        /// <returns>true if the signature is valid, otherwise false.</returns>
        public bool VerifySignature(byte[] data, ISigner hashAlgo, byte[] signature)
        {
            // Convert .NETs RSAParameters to Bouncy Castles RsaKeyParameters
            var key = new RsaKeyParameters(false, new BigInteger(Key.Modulus), new BigInteger(Key.Exponent));

            hashAlgo.Init(false, key);
            hashAlgo.BlockUpdate(data, 0, data.Length);

            return hashAlgo.VerifySignature(signature);
        }

        /// <summary>
        /// Gets asymmetric algorithm full name.
        /// </summary>
        /// <returns>The <see cref="System.Security.Cryptography.RSA"></see> full name.</returns>
        public string GetAlgorithmNameSignature()
        {
            return NameSignature;
        }
    }
}
