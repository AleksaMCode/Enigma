namespace Enigma.AlgorithmLibrary.Algorithms
{
    /// <summary>
    /// Interface for implementation all asymmetric-key algorithms.
    /// </summary>
    public interface IAsymmetricAlgorithm
    {
        /// <summary>
        /// Creates a asymmetric encrypted ciphertext stored in <see cref="byte"/>[] using the specified public key.
        /// </summary>
        /// <param name="data">Input data (opentext) used for encryption.</param>
        /// <returns>Encrypted data (ciphertext).</returns>
        byte[] Encrypt(byte[] data);

        /// <summary>
        /// Creates a asymmetric decrypted opentext stored in <see cref="byte"/>[] using the specified private key.
        /// </summary>
        /// <param name="data">Input data (ciphertext) used for decryption.</param>
        /// <returns>Decrypted data (opentext).</returns>
        byte[] Decrypt(byte[] data);


        /// <summary>
        /// Creates algorithms name signature..
        /// </summary>
        /// <returns>Algorithms signature. e.q. RSA</returns>
        string GetAlgorithmNameSignature();
    }
}
