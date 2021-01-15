namespace Enigma.AlgorithmLibrary.Algorithms
{
    /// <summary>
    /// Interface for implementation all symmetric-key algorithms.
    /// </summary>
    public interface IAlgorithm
    {
        /// <summary>
        /// Represents the secret key for the symmetric algorithm.
        /// </summary>
        byte[] Key { get; }

        /// <summary>
        /// Stores data such as initialization vector (IV).
        /// </summary>
        byte[] AdditionalData { get; }

        /// <summary>
        /// Creates a symmetric encrypted ciphertext stored in <see cref="byte"/>[] using the specified key, initialization vector (IV) and block cipher mode of operation.
        /// </summary>
        /// <param name="data">Input data (opentext) used for encryption.</param>
        /// <returns>Encrypted data (ciphertext).</returns>
        byte[] Encrypt(byte[] data);

        /// <summary>
        /// Creates a symmetric decrypted opentext stored in <see cref="byte"/>[] using the specified key, initialization vector (IV) and block cipher mode of operation.
        /// </summary>
        /// <param name="data">Input data (ciphertext) used for decryption.</param>
        /// <returns>Decrypted data (opentext).</returns>
        byte[] Decrypt(byte[] data);

        /// <summary>
        /// Creates algorithms name signature that contains algorithms name, key length and block cipher mode of operation separated with '<b>-</b>'.
        /// </summary>
        /// <returns>Algorithms signature. e.q. AES-256-CBC</returns>
        string GetAlgorithmNameSignature();
    }
}
