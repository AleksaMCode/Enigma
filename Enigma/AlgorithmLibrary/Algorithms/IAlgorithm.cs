using System.Security.Cryptography;

namespace Enigma
{
    /// <summary>
    /// Interface for implementation all encryption algorithms.
    /// </summary>
    public interface IAlgorithm
    {
        byte[] Key { get; }
        byte[] AdditionalData { get; }
        byte[] Encrypt(byte[] message, CipherMode mode = CipherMode.CBC);
        byte[] Decrypt(byte[] message, CipherMode mode = CipherMode.CBC);
        string GetAlgorithmNameSignature();
    }
}