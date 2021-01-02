using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Enigma.AlgorithmLibrary.Algorithms
{
    public class AesAlgorithm : IAlgorithm
    {
        public static readonly string signature = "AES";
        public byte[] Key { get; set; }
        public byte[] IV { get; set; }
    }
}
