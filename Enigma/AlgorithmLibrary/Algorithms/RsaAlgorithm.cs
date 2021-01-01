using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Enigma.AlgorithmLibrary.Algorithms
{
    public class RsaAlgorithm : IAlgorithm
    {
        public static readonly string NameSignature = "RSA";
        public RSAParameters Key { get; set; }
        byte[] IAlgorithm.Key => null;
        public int BlockSize { get; } = 115;
        public byte[] AdditionalData { get => null; }

        public RsaAlgorithm(RSAParameters rsaKeyParams)
        {
            Key = rsaKeyParams;
        }
    }
}
