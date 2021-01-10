using System;
using System.IO;

namespace Enigma
{
    public class EncryptedFile
    {
        internal readonly Stream EncrypteFileContent;

        /// <summary>
        /// Users public key is used for name encryption.
        /// </summary>
        public string EncriptedName { get; internal set; }

        public readonly string fileExtension = "at";
    }
}