using System.Security.Cryptography;

namespace Enigma.AlgorithmLibrary
{
    internal static class AlgorithmUtility
    {
        public static readonly int algoNameSignatureSize = 13;
        public static readonly int hashAlgoNameSignatureSize = 6;

        public static string GetNameSignatureFromAlgorithm(IAlgorithm code)
        {
            // TODO: finish
        }

        public static IAlgorithm GetAlgorithmFromNameSignature(string algoName)
        {
            // TODO: finish
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
    }
}
