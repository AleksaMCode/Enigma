using System;
using System.Linq;
using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace Enigma
{
    public class RsaAlgorithm : IAsymmetricAlgorithm
    {
        public static readonly string NameSignature = "RSA";

        public RSAParameters Key { get; set; }

        public RsaAlgorithm(RSAParameters rsaKeyParams)
        {
            Key = rsaKeyParams;
        }


        /// <summary>
        /// Compares public RSA key with a private RSA key. Random data is first encrypted using a private key
        /// and then decrypted with a public key. If the original data matches the obtained data then the keys match.
        /// </summary>
        /// <returns>true if the keys match, otherwise returns false.</returns>
        public static bool AreKeysMatched(RSAParameters publicKey, RSAParameters privateKey)
        {
            var data = new byte[16];
            new RNGCryptoServiceProvider().GetBytes(data);

            using var decryptRSA = new RSACryptoServiceProvider();
            using var encryptRSA = new RSACryptoServiceProvider();

            encryptRSA.ImportParameters(publicKey);
            decryptRSA.ImportParameters(privateKey);

            var decrypted = decryptRSA.Decrypt(encryptRSA.Encrypt(data, false), false);

            if (data.SequenceEqual(decrypted))
            {
                return true;
            }
            // else
            return false;
        }

        /// <summary>
        /// Compares public RSA key with a public key extracted from a private RSA key.
        /// This method is slower than AreKeysMatched method.
        /// </summary>
        /// <returns>true if the keys match, otherwise returns false.</returns>
        public static bool CompareKeys(RSAParameters publicKey, RSAParameters privateKey)
        {
            return ByteArrayCompare(publicKey.Modulus, privateKey.Modulus) && ByteArrayCompare(publicKey.Exponent, privateKey.Exponent);
        }

        /// <summary>
        /// Compares public RSA key with a public key extracted from a private RSA key.
        /// This method is slower than CompareKeys method.
        /// </summary>
        /// <returns>true if the keys match, otherwise returns false.</returns>
        [ObsoleteAttribute("This method is obsolete. Call CompareKeys instead.", true)]
        public static bool AreKeysMatched2(RSAParameters publicKey, RSAParameters privateKey)
        {
            var pemObject1 = DotNetUtilities.GetRsaPublicKey(publicKey);
            var rsaParams1 = DotNetUtilities.ToRSAParameters((RsaKeyParameters)pemObject1);

            var pemObject2 = DotNetUtilities.GetRsaKeyPair(privateKey);
            var rsaParams2 = DotNetUtilities.ToRSAParameters((RsaKeyParameters)pemObject2.Public);

            return ByteArrayCompare(rsaParams1.Modulus, rsaParams2.Modulus) && ByteArrayCompare(rsaParams1.Exponent, rsaParams2.Exponent);
        }

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

        public byte[] Signature(byte[] data, HashAlgorithm hashAlgo)
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
