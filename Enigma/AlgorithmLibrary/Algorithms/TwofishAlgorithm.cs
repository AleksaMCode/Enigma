using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Enigma.AlgorithmLibrary.Algorithms
{
    public class TwofishAlgorithm : IAlgorithm
    {
        public static readonly string NameSignature = "2fish";

        public static string ModeSignature = null;

        /// <summary>
        /// Twofish accepts a key of any length up to 256 bits. (NIST required the algorithm to accept 128-, 192-, and 256-bit keys.) 
        /// </summary>
        public byte[] Key { get; set; }

        /// <summary>
        /// Twofish has a block size of 128 bits.
        /// </summary>        
        public byte[] IV { get; set; }

        public byte[] AdditionalData { get => this.IV; }
    }
}
