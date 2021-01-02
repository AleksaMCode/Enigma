using System;
using System.Collections.Generic;
using System.Linq;
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
    }
}
