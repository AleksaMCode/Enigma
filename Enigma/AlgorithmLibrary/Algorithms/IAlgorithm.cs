using System.Security.Cryptography;

namespace Enigma
{
    /// <summary>
    /// Interface for implementation all symmetric-key algorithms.
    /// </summary>
    public interface IAlgorithm
    {
        byte[] Key { get; }
        byte[] AdditionalData { get; }
        byte[] Encrypt(byte[] data);
        byte[] Decrypt(byte[] data);
        string GetAlgorithmNameSignature();
    }
}