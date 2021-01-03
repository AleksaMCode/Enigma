﻿using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;

namespace Enigma
{
    public class TwofishAlgorithm : IAlgorithm
    {
        public static readonly string NameSignature = "2FISH";

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

        public TwofishAlgorithm(int keySize, string mode = "CBC")
        {
            Key = new byte[keySize]; // 32 B, 24 B or 16 B
            new RNGCryptoServiceProvider().GetBytes(Key);

            ModeSignature = mode;

            if (ModeSignature != "ECB")
            {
                IV = new byte[16];   // 16 B = 128 b
                new RNGCryptoServiceProvider().GetBytes(IV);
            }
            else
            {
                IV = null;
            }

        }

        public TwofishAlgorithm(byte[] key, byte[] iv, string mode = "CBC")
        {
            Key = key;
            IV = iv;
            ModeSignature = mode;
        }
    }
}
