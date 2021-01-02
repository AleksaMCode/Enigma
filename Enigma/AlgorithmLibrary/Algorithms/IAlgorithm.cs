using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Enigma
{
    /// <summary>
    /// Interface for implementation all encryption algorithms.
    /// </summary>
    public interface IAlgorithm
    {
        byte[] Key { get; }
        byte[] AdditionalData { get; }
        byte[] Encrypt(byte[] message);
        byte[] Decrypt(byte[] message);
        string GetAlgorithmNameSignature();
    }
}