namespace Enigma.AlgorithmLibrary
{
    /// <summary>
    /// EnigmaEFS works by encrypting a file with a unique symmetric key (Key + IV), also known as the File Encryption Key, or FEK.
    /// It uses a symmetric encryption algorithm because it takes less time to encrypt and decrypt large amounts of data than if an asymmetric key cipher is used.
    /// The symmetric encryption algorithm used will vary depending on the users choice. FEK also contains hashing algorithm that user chose to sign his file.
    /// FEK is then encrypted with a public key that is associated with the user who encrypted the file, 
    /// and this encrypted FEK is stored in the EFS part of the SECURITY_DESCRIPTOR header of the encrypted file.
    /// </summary>
    public class FileEncryptionKey
    {
        public string AlgorithmName { get; set; }

        public string HashAlgorithmName { get; set; }

        public byte[] Key { get; set; }

        public byte[] IV { get; set; }

        public FileEncryptionKey(string algoName, string hashName)
        {
            AlgorithmName = algoName;
            HashAlgorithmName = hashName;
        }
    }
}
