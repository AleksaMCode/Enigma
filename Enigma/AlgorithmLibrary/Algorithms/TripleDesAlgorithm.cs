using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Enigma.AlgorithmLibrary.Algorithms
{
    public class TripleDesAlgorithm : IAlgorithm
    {
        public static readonly string NameSignature = "3DES";

        public byte[] Key { get; set; }

        public byte[] IV { get; set; }

        public byte[] AdditionalData { get => this.IV; }

        public TripleDesAlgorithm()
        {
            Key = new byte[24];
            new RNGCryptoServiceProvider().GetBytes(Key);
            IV = new byte[16];
            new RNGCryptoServiceProvider().GetBytes(IV);
        }

        public TripleDesAlgorithm(byte[] key, byte[] iv)
        {
            Key = key;
            IV = iv;
        }
    }
}
