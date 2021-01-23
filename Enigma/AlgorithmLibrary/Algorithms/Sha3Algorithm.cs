using Org.BouncyCastle.Crypto.Digests;

namespace Enigma.AlgorithmLibrary.Algorithms
{
    /// <summary>
    /// Wrapper abstract class for Bouncy Castle Sha3Digest and SHA3 algorithms.
    /// </summary>
    public abstract class Sha3Algorithm
    {
        /// <summary>
        /// Computes the SHA3 hash value for the specified byte array.
        /// </summary>
        /// <param name="bitLength">Output size of hash in bits.</param>
        /// <param name="buffer">The input to compute the hash code for.</param>
        /// <returns>The computed hash code.</returns>
        public static byte[] ComputeHash(int bitLength, byte[] buffer)
        {
            var hashAlgorithm = new Sha3Digest(bitLength);
            hashAlgorithm.BlockUpdate(buffer, 0, buffer.Length);

            var computedHashCode = new byte[bitLength / 8];
            hashAlgorithm.DoFinal(computedHashCode, 0);

            return computedHashCode;
        }
    }
}
