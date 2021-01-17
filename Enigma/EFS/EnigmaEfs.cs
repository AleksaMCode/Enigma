using System;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using Enigma.CryptedFileParser;
using Enigma.Models;

namespace Enigma.EFS
{
    /// <summary>
    /// Allows to create, modify or manipulate an Enigma Encrypted File System.
    /// </summary>
    public class EnigmaEfs
    {
        private readonly string mountLocation = @"D:";
        private readonly string rootDir = @"D:\EnigmaEFS";
        private readonly string sharedDir = @"D:\EnigmaEFS\Shared";

        /// <summary>
        /// Information about the currently logged in user.
        /// </summary>
        private readonly UserInformation currentUser;

        /// <summary>
        /// Initializes a new instance of the <see cref="EnigmaEfs"/> class with the specified user information.
        /// </summary>
        /// <param name="user">Information about the currently logged in user from the database.</param>
        public EnigmaEfs(UserInformation user)
        {
            currentUser = user;

            // EFS "mount"
            if (Directory.Exists(mountLocation))
            {
                // create a new root directory if one isn't already created
                if (!Directory.Exists(rootDir))
                {
                    Directory.CreateDirectory(rootDir);
                }
                // create a new shared directory if one isn't already created
                if (!Directory.Exists(sharedDir))
                {
                    Directory.CreateDirectory(sharedDir);
                }

                if (!Directory.Exists(user.user.Username))
                {
                    Directory.CreateDirectory(user.user.Username);
                }
            }
            else
            {
                throw new Exception("Mount location for Enigma Encrypted File System is missing.");
            }
        }

        /// <summary>
        /// Check if the sufficient storage space is available to store a new file.
        /// </summary>
        /// <param name="size">Size of the file that is being uplaoded to EFS.</param>
        /// <returns></returns>
        public bool CanItBeStored(long size)
        {
            var availableFreeSpace = new DriveInfo(mountLocation).AvailableFreeSpace;
            if (size < availableFreeSpace)
            {
                return true;
            }
            else
            {
                return false;
            }
        }

        /// <summary>
        /// Check if the sufficient storage space on specified drive is available to store a new file.
        /// </summary>
        /// <param name="size">Size of the file that is being downloaded to file system.</param>
        /// <param name="driveName">Name of the drive where file will be stored.</param>
        /// <returns></returns>
        public bool CanItBeStored(long size, string driveName)
        {
            var availableFreeSpace = new DriveInfo(driveName).AvailableFreeSpace;
            if (size < availableFreeSpace)
            {
                return true;
            }
            else
            {
                return false;
            }
        }

        /// <summary>
        /// Uplaods selected file. File is first encrypted after which is stored on the specified path on encrypted file system.
        /// </summary>
        /// <param name="path">The fully qualified name of the new file.</param>
        /// <param name="pathOnEfs">Path on the encrypted file system where the file will be stored.</param>
        /// <param name="algorithmNameSignature">Name of the algorithm used for file encryption.</param>
        /// <param name="hashAlgorithmName">Name of the hashing algorithm used to create a file signature.</param>
        public void Upload(string path, string pathOnEfs, string algorithmNameSignature, string hashAlgorithmName)
        {
            var fileSize = new FileInfo(path).Length;

            if (fileSize > 4_000_000_000)
            {
                throw new Exception("File can't be larger than 4 GB.");
            }

            if (CanItBeStored(fileSize))
            {
                var fullFileName = path.Substring(path.LastIndexOf('\\') + 1);
                var originalFile = new OriginalFile(File.ReadAllBytes(path), fullFileName);

                var encryptedFile = new EncryptedFile(fullFileName, (uint)currentUser.user.Id, algorithmNameSignature, hashAlgorithmName, currentUser.PublicKey, currentUser.PrivateKey);
                var encryptedFileRaw = encryptedFile.Encrypt(originalFile, currentUser.user.Id, currentUser.PrivateKey);

                if (CanItBeStored(encryptedFileRaw.Length))
                {
                    using var stream = new FileStream(pathOnEfs + "\\" + encryptedFile.GetEncryptedFileFullName(), FileMode.Create);
                    using var writter = new BinaryWriter(stream);
                    writter.Write(encryptedFileRaw);
                }
                else
                {
                    throw new Exception("Insufficient storage available. File can't be uploaded.");
                }
            }
            else
            {
                throw new Exception("Insufficient storage available. File can't be uploaded.");
            }
        }

        /// <summary>
        /// Downlods selected encrypted file. File is first decrypted after which is stored on the specified path on file system.
        /// </summary>
        /// <param name="pathOnEfs">The name of the file to downloaded.</param>
        /// <param name="pathOnFs">Path on the file system where the file will be stored.</param>
        /// <param name="ownerPublicKey">Public RSA key from the file owner used to check files signature.</param>
        public void Download(string pathOnEfs, string pathOnFs, RSAParameters ownerPublicKey)
        {
            var encryptedFile = new EncryptedFile();
            var originalFile = encryptedFile.Decrypt(File.ReadAllBytes(pathOnEfs), currentUser.user.Id, currentUser.PrivateKey, ownerPublicKey);

            if (CanItBeStored(originalFile.FileContent.Length, pathOnFs.Substring(0, 2)))
            {
                using var stream = new FileStream(pathOnFs + "\\" + originalFile.GetOriginalFileFullName(), FileMode.Create);
                using var writter = new BinaryWriter(stream);
                writter.Write(originalFile.FileContent);
            }
            else
            {
                throw new Exception("Insufficient storage available. File can't be downloaded.");
            }
        }

        /// <summary>
        /// Creates a new <em>.txt</em> file on file system.
        /// </summary>
        /// <param name="text">Content of the file.</param>
        /// <param name="pathOnFs">Path on the file system where the file will be stored.</param>
        /// <param name="fileName">Name of the .txt file.</param>
        public void CreateTxtFile(string text, string pathOnFs, string fileName)
        {
            var textFile = new OriginalFile(Encoding.ASCII.GetBytes(text), fileName + ".txt");

            using var stream = new FileStream(pathOnFs + "\\" + textFile.GetOriginalFileFullName(), FileMode.Create);
            using var writter = new BinaryWriter(stream);
            writter.Write(textFile.FileContent);
        }

        /// <summary>
        /// Edits an existing <em>.txt</em> file on file system by overwriting the original file.
        /// </summary>
        /// <param name="text">Content from the .txt file.</param>
        /// <param name="pathOnFs">Path on the file system where file is stored which includes files name.</param>
        public void EditTxtFile(string text, string pathOnFs)
        {
            var fileName = pathOnFs.Substring(pathOnFs.LastIndexOf('\\') + 1);
            if (fileName.Substring(fileName.LastIndexOf('.') + 1).Equals("txt"))
            {
                var textFile = new OriginalFile(Encoding.ASCII.GetBytes(text), pathOnFs.Substring(pathOnFs.LastIndexOf('\\') + 1));

                using var stream = new FileStream(pathOnFs + "\\" + textFile.GetOriginalFileFullName(), FileMode.Create);
                using var writter = new BinaryWriter(stream);
                writter.Write(textFile.FileContent);
            }
            else
            {
                throw new Exception("File you are trying to edit isn't a .txt file");
            }
        }

        /// <summary>
        /// Deletes the specified file.
        /// </summary>
        /// <param name="path">The name of the file to be deleted. Wildcard characters are not supported.</param>
        public void DeleteFile(string path)
        {
            File.Delete(path);
        }

        /// <summary>
        /// Deletes the specified directory and and any subdirectories and files in the directory.
        /// </summary>
        /// <param name="path">The name of the directory to remove.</param>
        public void DeleteDirectory(string path)
        {
            Directory.Delete(path, true);
        }

        /// <summary>
        /// Reads users encrypted file. File is first decrypted and stored as a temporary file in temporary folder after which is opened in a default app for that file set on the computer. 
        /// </summary>
        /// <param name="pathOnEfs">The name of the encrypted file including files path and encrypted name with .at extension.</param>
        /// <param name="ownerPublicKey">Public RSA key from the file owner used to check files signature.</param>
        public void ReadFile(string pathOnEfs, RSAParameters ownerPublicKey)
        {
            var encryptedFile = new EncryptedFile();
            var originalFile = encryptedFile.Decrypt(File.ReadAllBytes(pathOnEfs), currentUser.user.Id, currentUser.PrivateKey, ownerPublicKey);
            var tempFilePath = Path.GetTempPath() + "Enigma-" + Guid.NewGuid().ToString() + "." + originalFile.FileExtension;

            using (var stream = new FileStream(tempFilePath, FileMode.Create))
            {
                using var writter = new BinaryWriter(stream);
                writter.Write(originalFile.FileContent);
            }

            var startInfo = new ProcessStartInfo(tempFilePath);
            Process.Start(startInfo);
        }

        /// <summary>
        /// Removes all temporary files created while reading encrypted files. This method is called when application is closed.
        /// </summary>
        public void RemoveTempFiles()
        {
            var filesToDelete = Directory.GetFiles(Path.GetTempPath(), "Enigma-*");
            foreach (var fileName in filesToDelete)
            {
                File.Delete(fileName);
            }
        }
    }
}
