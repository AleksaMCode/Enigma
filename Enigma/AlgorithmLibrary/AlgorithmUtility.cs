using System;
using System.Security.Cryptography;
using Enigma.AlgorithmLibrary.Algorithms;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;

namespace Enigma.AlgorithmLibrary
{
    /// <summary>
    /// Helper class used for symmetric encryption/decryption.
    /// </summary>
    internal static class AlgorithmUtility
    {
        /// <summary>
        /// Maximum length of the algorithm name signature.
        /// </summary>
        public static readonly int maxAlgoNameSignatureSize = 13;

        /// <summary>
        /// Maximum length of the hash algorithm name signature.
        /// </summary>
        public static readonly int maxHashAlgoNameSignatureSize = 10;

        /// <summary>
        /// Parses key size stored as <see cref="string"/> to <see cref="int"/>.
        /// </summary>
        /// <param name="keySizeAscii">Size of the key used in symmetric algorithm.</param>
        /// <returns>Parsed key size in bytes.</returns>
        public static int ParseKeySize(string keySizeAscii)
        {
            return Convert.ToInt32(keySizeAscii) / 8;
        }

        /// <summary>
        /// Gets the algorithm name signature from the symmetric algorithm interface <see cref="IAlgorithm"/>.
        /// </summary>
        /// <param name="algo">Symmetric algorithm interface used for encryption.</param>
        /// <returns>Algorithm name signature from the symmetric algorithms method <see cref="IAlgorithm.GetAlgorithmNameSignature"/>.</returns>
        public static string GetNameSignatureFromAlgorithm(IAlgorithm algo)
        {
            return (algo is AesAlgorithm) || (algo is CamelliaAlgorithm) || (algo is TwofishAlgorithm) || (algo is TripleDesAlgorithm)
                ? algo.GetAlgorithmNameSignature()
                : throw new CryptographicException("Unknown cryptor with code '" + algo.GetAlgorithmNameSignature() + "' used.");
        }

        /// <summary>
        /// Gets the symmetric algorithm from the algorithms name signature.
        /// </summary>
        /// <param name="algoName">Algorithms name signature.</param>
        /// <returns>New instance of the symmetric algorithm.</returns>
        public static IAlgorithm GetAlgorithmFromNameSignature(string algoName)
        {
            if (algoName.Length > maxAlgoNameSignatureSize)
            {
                throw new CryptographicException("Unknown cryptor with code '" + algoName + "' used.");
            }

            // split the name in AlgoName, KeySize and CipherMode for AES, Camellia and Twofish, e.q. AES-256-OFB
            // split the name in AlgoName, Ciphermode for 3DES, e.q. 3DSES-OFB
            var tokens = algoName.Split('-');

            if (tokens[0].Equals("AES"))
            {
                return new AesAlgorithm(ParseKeySize(tokens[1]), tokens[2]);
            }
            else if (tokens[0].Equals("2FISH"))
            {
                return new TwofishAlgorithm(ParseKeySize(tokens[1]), tokens[2]);
            }
            else if (tokens[0].Equals("CAMLL"))
            {
                return new CamelliaAlgorithm(ParseKeySize(tokens[1]), tokens[2]);
            }
            // 3DES
            else
            {
                return new TripleDesAlgorithm(tokens[1]);
            }
        }

        /// <summary>
        /// Gets the symmetric algorithm from the algorithms name signature, key and iv value.
        /// </summary>
        /// <param name="algoName">Algorithms name signature.</param>
        /// <param name="key">Algorithms key.</param>
        /// <param name="iv">Algoirthms iv.</param>
        /// <returns>New instance of the symmetric algorithm.</returns>
        public static IAlgorithm GetAlgorithmFromNameSignature(string algoName, byte[] key, byte[] iv)
        {
            if (algoName.Length > maxAlgoNameSignatureSize)
            {
                throw new CryptographicException("Unknown cryptor with code '" + algoName + "' used.");
            }

            // split the name in AlgoName, KeySize and CipherMode for AES, Camellia and Twofish, e.q. AES-256-OFB
            // split the name in AlgoName, Ciphermode for 3DES, e.q. 3DSES-OFB
            var tokens = algoName.Split('-');

            if (tokens[0].Equals("AES"))
            {
                return new AesAlgorithm(key, iv, tokens[2]);
            }
            else if (tokens[0].Equals("2FISH"))
            {
                return new TwofishAlgorithm(key, iv, tokens[2]);
            }
            else if (tokens[0].Equals("CAMLL"))
            {
                return new CamelliaAlgorithm(key, iv, tokens[2]);
            }
            else // 3DES
            {
                return new TripleDesAlgorithm(key, iv, tokens[2]);
            }
        }

        /// <summary>
        /// Gets the hash algorithm name signature from the hash algorithm class <see cref="HashAlgorithm"/>.
        /// </summary>
        /// <param name="hashAlgo">Hash algorithm used for hashing.</param>
        /// <returns>Hash algorithm name signature.</returns>
        public static string GetNameSignatureFromHashAlgo(HashAlgorithm hashAlgo)
        {
            if (hashAlgo is MD5)
            {
                return "MD5";
            }
            else if (hashAlgo is SHA1)
            {
                return "SHA1";
            }
            else if (hashAlgo is SHA256)
            {
                return "SHA256";
            }
            else if (hashAlgo is SHA384)
            {
                return "SHA384";
            }
            else if (hashAlgo is SHA512)
            {
                return "SHA512";
            }
            else
            {
                throw new CryptographicException("Unknown Hash Algorithm used.");
            }
        }

        /// <summary>
        /// Gets the hash algorithm from the hash algorithm name signature.
        /// </summary>
        /// <param name="algoName">Hash algorithm name signature.</param>
        /// <returns>New instance of the hash algorithm.</returns>
        public static HashAlgorithm GetHashAlgoFromNameSignature(string algoName)
        {
            if (algoName.Length > maxHashAlgoNameSignatureSize)
            {
                throw new CryptographicException("Unknown hasher with code '" + algoName + "' used.");
            }

            if (algoName.Equals("MD5"))
            {
                return MD5.Create();
            }
            else if (algoName.Equals("SHA1"))
            {
                return SHA1.Create();
            }
            else if (algoName.Equals("SHA256"))
            {
                return SHA256.Create();
            }
            else if (algoName.Equals("SHA384"))
            {
                return SHA384.Create();
            }
            else if (algoName.Equals("SHA512"))
            {
                return SHA512.Create();
            }
            else
            {
                throw new CryptographicException("Unknown hasher with code '" + algoName + "' used.");
            }
        }

        /// <summary>
        /// Gets the hash algorithm <see cref="ISigner"/> from the hash algorithm name signature.
        /// </summary>
        /// <param name="algoName">Hash algorithm name signature.</param>
        /// <returns>New instance of the hash algorithm interface.</returns>
        public static ISigner GetHashSignerFromNameSignature(string algoName)
        {
            if (algoName.Length > maxHashAlgoNameSignatureSize)
            {
                throw new CryptographicException("Unknown hasher with code '" + algoName + "' used.");
            }

            var withRsaString = "withRSA";

            switch (algoName)
            {
                case "MD2":
                {
                    return SignerUtilities.GetSigner(algoName + withRsaString);
                }
                case "MD4":
                {
                    return SignerUtilities.GetSigner(algoName + withRsaString);
                }
                case "SHA-224":
                {
                    return SignerUtilities.GetSigner(algoName.Replace("-", "") + withRsaString);
                }
                case "RIPEMD-128":
                {
                    return SignerUtilities.GetSigner(algoName.Replace("-", "") + withRsaString);
                }
                case "RIPEMD-160":
                {
                    return SignerUtilities.GetSigner(algoName.Replace("-", "") + withRsaString);
                }
                case "RIPEMD-256":
                {
                    return SignerUtilities.GetSigner(algoName.Replace("-", "") + withRsaString);
                }
                default:
                {
                    throw new CryptographicException("Unknown hasher with code '" + algoName + "' used.");
                }
            }
        }

        /// <summary>
        /// Gets the symmetric algorithm mode of operation <see cref="CipherMode"/> from the mode name.
        /// </summary>
        /// <param name="mode">Mode of operation name.</param>
        /// <returns><see cref="CipherMode"/> enum that matches modes name.</returns>
        public static CipherMode GetCipherMode(string mode)
        {
            switch (mode)
            {
                case "CBC":
                {
                    return CipherMode.CBC;
                }
                case "ECB":
                {
                    return CipherMode.ECB;
                }
                case "OFB":
                {
                    return CipherMode.OFB;
                }
                case "CFB":
                {
                    return CipherMode.CFB;
                }
                default:
                {
                    throw new CryptographicException("Unknown block cipher mode '" + mode + "' used.");
                }
            }
        }

        /// <summary>
        /// Gets the Iv size for the currently used symmetric algorithm.
        /// </summary>
        /// <param name="algoName">Name of the symmetric algorithm.</param>
        /// <returns>8 B size for 3DES, otherwise 16 B size.</returns>
        public static int GetIvSizeFromAlgoName(string algoName)
        {
            switch (algoName)
            {
                case "3DES":
                {
                    return 8;
                }
                default: // AES, CAMLL or 2FISH
                {
                    return 16;
                }
            }
        }
    }
}
