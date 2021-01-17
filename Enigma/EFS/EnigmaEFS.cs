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
    /// Allows to create, modify or manipulate an Enigma Encripted File System.
    /// </summary>
    public class EnigmaEfs
    {
        private readonly string mountLocation = @"D:";
        private readonly string rootDir = @"D:\EnigmaEFS";
        private readonly string sharedDir = @"D:\EnigmaEFS\Shared";
        private readonly UserInformation currentUser;
        public long AvailableFreeSpace { get; set; }
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
            }
            else
            {
                // error handle
            }
            // set AvailableFreeSpace value
            AvailableFreeSpace = new DriveInfo(mountLocation).AvailableFreeSpace;
        }

        public bool CanItBeStored(long size)
        {
            AvailableFreeSpace = new DriveInfo(mountLocation).AvailableFreeSpace;
            if (size < AvailableFreeSpace)
            {
                return true;
            }
            else
            {
                return false;
            }
        }

        public void Upload(string locationOfFile, string locationOnEfs, string algorithmNameSignature, string hashAlgorithmName)
        {
            var fileSize = new FileInfo(locationOfFile).Length;

            if (fileSize > 4_000_000_000)
            {
                throw new Exception("File can't be larger than 4 GB.");
            }

            if (CanItBeStored(fileSize))
            {
                var fullFileName = locationOfFile.Substring(locationOfFile.LastIndexOf('\\') + 1);
                var originalFile = new OriginalFile(File.ReadAllBytes(locationOfFile), fullFileName);

                var encryptedFile = new EncryptedFile(fullFileName, (uint)currentUser.user.Id, algorithmNameSignature, hashAlgorithmName, currentUser.PublicKey, currentUser.PrivateKey);
                var encryptedFileRaw = encryptedFile.Encrypt(originalFile, currentUser.user.Id, currentUser.PrivateKey);

                using var stream = new FileStream(locationOnEfs + "\\" + encryptedFile.GetEncryptedFileFullName(), FileMode.Create);
                using var writter = new BinaryWriter(stream);
                writter.Write(encryptedFileRaw);
            }
            else
            {
                throw new Exception("Insufficient storage available.");
            }
        }

        public void Download(string locationOnEfs, string locationOnFs, RSAParameters ownerPublicKey)
        {
            var encryptedFile = new EncryptedFile();
            var originalFile = encryptedFile.Decrypt(File.ReadAllBytes(locationOnEfs), currentUser.user.Id, currentUser.PrivateKey, ownerPublicKey);

            using var stream = new FileStream(locationOnFs + "\\" + originalFile.GetOriginalFileFullName(), FileMode.Create);
            using var writter = new BinaryWriter(stream);
            writter.Write(originalFile.FileContent);
        }

        public void CreateTxtFile(string text, string locationOnFs, string fileName)
        {
            var textFile = new OriginalFile(Encoding.ASCII.GetBytes(text), fileName + ".txt");

            using var stream = new FileStream(locationOnFs + "\\" + textFile.GetOriginalFileFullName(), FileMode.Create);
            using var writter = new BinaryWriter(stream);
            writter.Write(textFile.FileContent);
        }

        public void EditTxtFile(string text, string locationOnFs)
        {
            var textFile = new OriginalFile(Encoding.ASCII.GetBytes(text), locationOnFs.Substring(locationOnFs.LastIndexOf('\\') + 1));

            using var stream = new FileStream(locationOnFs + "\\" + textFile.GetOriginalFileFullName(), FileMode.Create);
            using var writter = new BinaryWriter(stream);
            writter.Write(textFile.FileContent);
        }

        public void DeleteFile(string path)
        {
            File.Delete(path);
        }

        public void DeleteDirectory(string path)
        {
            Directory.Delete(path, true);
        }

        public void ReadFile(string locationOnEfs, RSAParameters ownerPublicKey, out string tempFilePath)
        {
            var encryptedFile = new EncryptedFile();
            var originalFile = encryptedFile.Decrypt(File.ReadAllBytes(locationOnEfs), currentUser.user.Id, currentUser.PrivateKey, ownerPublicKey);
            tempFilePath = Path.GetTempPath() + "Enigma-" + Guid.NewGuid().ToString() + "." + originalFile.FileExtension;

            using (var stream = new FileStream(tempFilePath, FileMode.Create))
            {
                using var writter = new BinaryWriter(stream);
                writter.Write(originalFile.FileContent);
            }

            var startInfo = new ProcessStartInfo(tempFilePath);
            Process.Start(startInfo);
        }
    }
}
