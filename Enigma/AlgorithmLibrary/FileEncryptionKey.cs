using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Enigma
{
    /// <summary>
    /// EnigmaEFS works by encrypting a file with a unique symmetric key (Key + IV/Salt), also known as the File Encryption Key, or FEK.
    /// It uses a symmetric encryption algorithm because it takes less time to encrypt and decrypt large amounts of data than if an asymmetric key cipher is used.
    /// The symmetric encryption algorithm used will vary depending on the users choice.
    /// The FEK (the symmetric key that is used to encrypt the file) is then encrypted with a public key that is associated with the user who encrypted the file, 
    /// and this encrypted FEK is stored in the EFS part of the SECURITY_DESCRIPTOR header of the encrypted file.
    /// </summary>
    public class FileEncryptionKey
    {
        public string AlgorithmName { get; set; }
        public byte[] Key { get; set; }
        public byte[] IV { get; set; }

        public FileEncryptionKey(string algoName, IAlgorithm algo)
        {
            //TODO: complete
        }
    }
}
