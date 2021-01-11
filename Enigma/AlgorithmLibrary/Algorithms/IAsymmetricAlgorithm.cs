namespace Enigma.AlgorithmLibrary.Algorithms
{
    /// <summary>
    /// Interface for implementation all asymmetric-key algorithms.
    /// </summary>
    public interface IAsymmetricAlgorithm
    {
        byte[] Encrypt(byte[] data);

        byte[] Decrypt(byte[] data);

        string GetAlgorithmNameSignature();
    }
}
