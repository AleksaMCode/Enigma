using System;
using System.Security.Cryptography;

namespace Enigma
{
    internal static class AlgorithmUtility
    {
        public static readonly int algoNameSignatureSize = 13;
        public static readonly int hashAlgoNameSignatureSize = 6;

        public static string GetNameSignatureFromAlgorithm(IAlgorithm algo)
        {
            if ((algo is AesAlgorithm) || (algo is CamelliaAlgorithm) || (algo is TwofishAlgorithm) || (algo is TripleDesAlgorithm))
            {
                return algo.GetAlgorithmNameSignature();
            }
            else
            {
                throw new UnknownCryptAlgoException(algo.GetAlgorithmNameSignature());
            }
        }

        private static int ParseKeySize(string keySizeAscii)
        {
            return Convert.ToInt32(keySizeAscii) / 8;
        }

        public static IAlgorithm GetAlgorithmFromNameSignature(string algoName)
        {
            // remove padding
            algoName = algoName.Substring(0, algoName.IndexOf('0'));

            // split the name in AlgoName, KeySize and CipherMode for AES, Camellia and Twofish
            // split the name in AlgoName, Ciphermode for 3DES
            string[] tokens = algoName.Split('-');

            if (tokens[0].Equals("AES"))
            {
                return new AesAlgorithm(ParseKeySize(tokens[1]), tokens[3]);
            }
            else if (tokens[0].Equals("2FISH"))
            {
                return new TwofishAlgorithm(ParseKeySize(tokens[1]), tokens[3]);
            }
            else if (tokens[0].Equals("CAMLL"))
            {
                return new CamelliaAlgorithm(ParseKeySize(tokens[1]), tokens[3]);
            }
            // 3DES
            else
            {
                return new TripleDesAlgorithm(tokens[1]);
            }

        }

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
                throw new UnknownHashAlgoException("Unknown Hash Algorithm used.");
            }
        }

        public static HashAlgorithm GetHashAlgoFromNameSignature(string algoName)
        {
            if (algoName.Length != hashAlgoNameSignatureSize)
            {
                throw new UnknownHashAlgoException(algoName);
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
                throw new UnknownHashAlgoException(algoName);
            }
        }

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
                case "CTS":
                    {
                        return CipherMode.CTS;
                    }
                default:
                    {
                        throw new UnknownCipherModeException("mode");
                    }
            }
        }
    }
}