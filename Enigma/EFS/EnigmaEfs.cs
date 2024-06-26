using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using Enigma.AlgorithmLibrary.Algorithms;
using Enigma.CryptedFileParser;
using Enigma.EFS.Attributes;
using Enigma.Models;

namespace Enigma.EFS
{
    /// <summary>
    /// Allows to create, modify or manipulate an Enigma Encrypted File System.
    /// </summary>
    public class EnigmaEfs
    {
        /// <summary>
        /// Mount directory for Enigma EFS.
        /// </summary>
        private readonly string mountLocation;

        /// <summary>
        /// Root directory of Enigma EFS that contains Shared and user's directories.
        /// </summary>
        public readonly string RootDir;

        public readonly string SharedDir;

        public string UserDir;

        /// <summary>
        /// Information about the currently logged-in user.
        /// </summary>
        public readonly UserInformation currentUser;

        /// <summary>
        /// Information on whether the user has a private RSA USB key. 
        /// </summary>
        public bool UsbKey => currentUser.UsbKey;

        /// <summary>
        /// Initializes a new instance of the <see cref="EnigmaEfs"/> class with the specified user information.
        /// </summary>
        /// <param name="user">Information about the currently logged in user from the database.</param>
        /// <param name="rootDir">Path to Enigma's Efs root directory.</param>
        /// <param name="passwordRaw">Raw password in bytes.</param>
        public EnigmaEfs(UserInformation user, string rootDir, byte[] passwordRaw)
        {
            mountLocation = rootDir.Substring(0, 2);
            RootDir = rootDir;
            SharedDir = rootDir + "\\Shared";

            currentUser = user;
            UserDir = GetUserDirName(passwordRaw);

            // EFS "mount"
            if (Directory.Exists(mountLocation))
            {
                // create a new root directory if one isn't already created
                if (!Directory.Exists(rootDir))
                {
                    Directory.CreateDirectory(rootDir);
                }
                // create a new shared directory if one isn't already created
                if (!Directory.Exists(SharedDir))
                {
                    Directory.CreateDirectory(SharedDir);
                }

                if (!Directory.Exists(rootDir + "\\" + UserDir))
                {
                    Directory.CreateDirectory(rootDir + "\\" + UserDir);
                }
            }
            else
            {
                throw new Exception("Mount location for Enigma Encrypted File System is missing.");
            }
        }

        /// <summary>
        /// Encrypt user's root directory name.
        /// </summary>
        /// <param name="passwordRaw">Raw password in bytes.</param>
        /// <returns>Encrypted username.</returns>
        public string GetUserDirName(byte[] passwordRaw)
        {
            var hash = SHA512.Create().ComputeHash(passwordRaw);
            var key = new byte[32];
            var iv = new byte[16];

            Buffer.BlockCopy(hash, 0, key, 0, 32);
            Buffer.BlockCopy(hash, 32, iv, 0, 16);

            var usernameRaw = Encoding.ASCII.GetBytes(currentUser.Username);

            var encryptedName = Convert.ToBase64String(new AesAlgorithm(key, iv, "OFB").Encrypt(usernameRaw));
            encryptedName = encryptedName.Replace('/', '$');

            return encryptedName;
        }

        /// <summary>
        /// Checks if the sufficient storage space is available to store a new file.
        /// </summary>
        /// <param name="size">Size of the file that is being uplaoded to EFS.</param>
        /// <returns>true if file can be stored on EFS, otherwise it returns false.</returns>
        private bool CanItBeStored(long size)
        {
            return size < new DriveInfo(mountLocation).AvailableFreeSpace;
        }

        /// <summary>
        /// Checks if the sufficient storage space on specified drive is available to store a new file.
        /// </summary>
        /// <param name="size">Size of the file that is being downloaded to file system.</param>
        /// <param name="driveName">Name of the drive where file will be stored.</param>
        /// <returns>true if file can be stored on FS, otherwise it returns false.</returns>
        private bool CanItBeStored(long size, string driveName)
        {
            return size < new DriveInfo(driveName).AvailableFreeSpace;
        }

        /// <summary>
        /// Uploads selected file. File is first encrypted after which is stored on the specified path on encrypted file system.
        /// </summary>
        /// <param name="pathOnFs">The fully qualified name of the new file.</param>
        /// <param name="pathOnEfs">Path on the encrypted file system where the file will be stored.</param>
        /// <param name="algorithmNameSignature">Name of the algorithm used for file encryption.</param>
        /// <param name="hashAlgorithmName">Name of the hashing algorithm used to create a file signature.</param>
        /// <param name="deleteOriginal">Flag used to remove an original copy of file.</param>
        /// <returns>Encrypted name of the file.</returns>
        public string Upload(string pathOnFs, string pathOnEfs, string algorithmNameSignature, string hashAlgorithmName, bool deleteOriginal = false)
        {
            if (Convert.ToDateTime(currentUser.CertificateExpirationDate) < DateTime.Now)
            {
                throw new Exception("Your certificate has expired. You cannot import any new files.");
            }

            // var fileSize = new FileInfo(pathOnFs).Length;
            var fullFileName = pathOnFs.Substring(pathOnFs.LastIndexOf('\\') + 1);
            var originalFile = new OriginalFile(File.ReadAllBytes(pathOnFs), fullFileName);

            var encryptedName = Upload(originalFile, pathOnEfs, algorithmNameSignature, hashAlgorithmName);

            if (deleteOriginal)
            {
                DeleteFile(pathOnFs);
            }

            return encryptedName;
        }

        /// <summary>
        /// Uploads selected file. File is first encrypted after which is stored on the specified path on encrypted file system.
        /// </summary>
        /// <param name="originalFile">Original, unencrypted file.</param>
        /// <param name="pathOnEfs">Path on the encrypted file system where the file will be stored.</param>
        /// <param name="algorithmNameSignature">Name of the algorithm used for file encryption.</param>
        /// <param name="hashAlgorithmName">Name of the hashing algorithm used to create a file signature.</param>
        /// <returns>Encrypted name of the file.</returns>
        public string Upload(OriginalFile originalFile, string pathOnEfs, string algorithmNameSignature, string hashAlgorithmName)
        {
            CertificateCheck("You cannot import any new files.");

            string encryptedName;

            if (originalFile.FileSize > 1_900_000_000)
            {
                throw new Exception("File can't be larger than 2 GB.");
            }

            if (CanItBeStored(originalFile.FileSize))
            {
                var encryptedFile = new EncryptedFile(originalFile.GetOriginalFileFullName(), (uint)currentUser.Id, algorithmNameSignature, hashAlgorithmName, currentUser.PublicKey, currentUser.PrivateKey);
                var encryptedFileRaw = encryptedFile.Encrypt(originalFile, currentUser.Id, currentUser.PrivateKey);
                encryptedName = encryptedFile.EncryptedName;

                // var userPrivateKey = currentUser.GetPrivateKey(privateKeyPath, password);

                if (CanItBeStored(encryptedFileRaw.Length))
                {
                    CreateFile(encryptedFileRaw, pathOnEfs + "\\" + encryptedFile.GetEncryptedFileFullName());
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

            return encryptedName;
        }

        /// <summary>
        /// Downloads selected encrypted file. File is first decrypted after which is stored on the specified path on file system.
        /// </summary>
        /// <param name="pathOnEfs">The name of the file to downloaded.</param>
        /// <param name="pathOnFs">Path on the file system where the file will be stored.</param>
        /// <param name="ownerPublicKey">Public RSA key from the file owner used to check files signature.</param>
        public void Download(string pathOnEfs, string pathOnFs, RSAParameters ownerPublicKey)
        {
            var encryptedFile = new EncryptedFile(pathOnEfs.Substring(pathOnEfs.LastIndexOf('\\') + 1).Split('.')[0]);
            var originalFile = encryptedFile.Decrypt(File.ReadAllBytes(pathOnEfs), currentUser.Id, currentUser.PrivateKey, ownerPublicKey);

            if (CanItBeStored(originalFile.FileContent.Length, pathOnFs.Substring(0, 2)))
            {
                // write a new unencrypted file
                CreateFile(originalFile.FileContent, pathOnFs/* + "\\" + originalFile.GetOriginalFileFullName()*/);

                // override existing encrypted file
                CreateFile(encryptedFile.Flush(), pathOnEfs);
            }
            else
            {
                throw new Exception("Insufficient storage available. File can't be downloaded.");
            }
        }

        /// <summary>
        /// Downloads selected encrypted file. File is first decrypted after which is stored in memory.
        /// </summary>
        /// <param name="pathOnEfs">The name of the file to downloaded.</param>
        /// <param name="ownerPublicKey">Public RSA key from the file owner used to check files signature.</param>
        public OriginalFile DownloadInMemory(string pathOnEfs, RSAParameters ownerPublicKey)
        {
            return new EncryptedFile(pathOnEfs.Substring(pathOnEfs.LastIndexOf('\\') + 1).Split('.')[0])
                .Decrypt(File.ReadAllBytes(pathOnEfs), currentUser.Id, currentUser.PrivateKey, ownerPublicKey);
        }

        /// <summary>
        /// Updates selected encrypted file with a specified unencrypted file from file system. Original file name will be unchanged.
        /// </summary>
        /// <param name="pathOnEfs">The name of the file to update.</param>
        /// <param name="pathOnFs">Path on the file system where the update file is stored.</param>
        /// <param name="originalFileExt">Allowed file type used for file update..</param>
        public void Update(string pathOnEfs, string pathOnFs, string originalFileExt)
        {
            var fileSize = new FileInfo(pathOnFs).Length;

            if (fileSize > 1_900_000_000)
            {
                throw new Exception("File can't be larger than 2 GB.");
            }

            if (!CanItBeStored(fileSize))
            {
                throw new Exception("Insufficient storage available. File can't be uploaded.");
            }

            var fullFileName = pathOnFs.Substring(pathOnFs.LastIndexOf('\\') + 1);

            //var userPrivateKey = currentUser.GetPrivateKey(privateKeyPath, password);

            //var originalFileExt = new EncryptedFile(pathOnEfs.Substring(pathOnEfs.LastIndexOf('\\') + 1).Split('.')[0])
            //    .Decrypt(File.ReadAllBytes(pathOnEfs), currentUser.Id, currentUser.PrivateKey, ownerPublicKey).GetOriginalFileFullName().Split('.')[1];

            // update method restriction
            if ("." + originalFileExt != Path.GetExtension(fullFileName))
            {
                throw new Exception("File type must remain the same when updating an existing encrypted file.");
            }

            Update(pathOnEfs, new OriginalFile(File.ReadAllBytes(pathOnFs), fullFileName));
        }

        /// <summary>
        /// Updates selected encrypted file with a specified unencrypted file.
        /// </summary>
        /// <param name="pathOnEfs">The name of the file to update.</param>
        /// <param name="updateFile">Updated, unencrypted file.</param>
        public void Update(string pathOnEfs, OriginalFile updateFile)
        {
            CertificateCheck("You cannot update files.");

            if (updateFile.FileSize > 2_000_000_000)
            {
                throw new Exception("File can't be larger than 2 GB.");
            }

            if (!CanItBeStored(updateFile.FileSize))
            {
                throw new Exception("Insufficient storage available. File can't be uploaded.");
            }

            var encryptedFile = new EncryptedFile(pathOnEfs.Substring(pathOnEfs.LastIndexOf('\\') + 1).Split('.')[0]);
            var updatedEncryptedFileRaw = encryptedFile.Update(updateFile, File.ReadAllBytes(pathOnEfs), currentUser.Id, currentUser.PrivateKey);

            // Name update is always necessary because file's IV has been changed and possibly a new file has a different name.
            encryptedFile.NameEncryption(updateFile.GetOriginalFileFullName(),
                new AesAlgorithm(((SecurityDescriptor)encryptedFile.Headers[1]).GetKey((int)currentUser.Id, currentUser.PrivateKey),
                ((SecurityDescriptor)encryptedFile.Headers[1]).IV, "OFB"));

            // delete the old encrypted file
            DeleteFile(pathOnEfs);

            if (CanItBeStored(updatedEncryptedFileRaw.Length))
            {
                CreateFile(updatedEncryptedFileRaw, pathOnEfs.Substring(0, pathOnEfs.LastIndexOf('\\')) + "\\" + encryptedFile.GetEncryptedFileFullName());
            }
            else
            {
                throw new Exception("Insufficient storage available. File can't be updated.");
            }
        }

        /// <summary>
        /// Checks if user's certificate has expired or if it's been revoked.
        /// </summary>
        /// <param name="msg"></param>
        private void CertificateCheck(string msg, UserInformation user = null)
        {
            if (Convert.ToDateTime(user != null ? user.CertificateExpirationDate : currentUser.CertificateExpirationDate) < DateTime.Now)
            {
                throw new Exception($"Certificate has expired. {msg}");
            }
            else if (user != null ? user.Revoked : currentUser.Revoked)
            {
                throw new Exception($"Certificate has been revoked. {msg}");
            }
        }

        /// <summary>
        /// Shares a file with other specific user on EnigmaEfs.
        /// </summary>
        /// <param name="pathOnEfs">The name of the shared file.</param>
        /// <param name="shareUser">User you are sharing a file with.</param>
        public void Share(string pathOnEfs, UserInformation shareUser)
        {
            CertificateCheck($"You cannot share files with {shareUser.Username}.");

            var encryptedFile = new EncryptedFile(pathOnEfs.Substring(pathOnEfs.LastIndexOf('\\') + 1).Split('.')[0]);
            var updatedEncryptedFileRaw = encryptedFile.Share(File.ReadAllBytes(pathOnEfs), currentUser.Id, shareUser.Id, currentUser.PrivateKey, shareUser.PublicKey);

            if (CanItBeStored(updatedEncryptedFileRaw.Length))
            {
                CreateFile(updatedEncryptedFileRaw, SharedDir + "\\" + encryptedFile.GetEncryptedFileFullName());

                // When first sharing a file from user folder to shared folder.
                if (pathOnEfs.Substring(0, pathOnEfs.LastIndexOf('\\')) != SharedDir)
                {
                    DeleteFile(pathOnEfs);
                }
            }
            else
            {
                throw new Exception("Insufficient storage available. File can't be updated.");
            }
        }

        /// <summary>
        /// Unshares a file with specific user on EnigmaEfs.
        /// </summary>
        /// <param name="pathOnEfs">The name of the shared file.</param>
        /// <param name="userId">Unique user identifier from the database.</param>
        public void Unshare(string pathOnEfs, int userId)
        {
            var encryptedFile = new EncryptedFile(pathOnEfs.Substring(pathOnEfs.LastIndexOf('\\') + 1).Split('.')[0]);
            var updatedEncryptedFileRaw = encryptedFile.Unshare(File.ReadAllBytes(pathOnEfs), currentUser.Id, userId, out var numberOfSharedUsers);

            if (CanItBeStored(updatedEncryptedFileRaw.Length))
            {
                // File is moved from shared folder to user's folder.
                if (numberOfSharedUsers != 1)
                {
                    CreateFile(updatedEncryptedFileRaw, SharedDir + "\\" + encryptedFile.GetEncryptedFileFullName());
                }
                // If no other user other than file owner can access a file, it's moved from shared folder to file owner's folder.
                else
                {
                    CreateFile(updatedEncryptedFileRaw, RootDir + "\\" + UserDir + "\\" + encryptedFile.GetEncryptedFileFullName());
                    DeleteFile(pathOnEfs);
                }
            }
            else
            {
                throw new Exception("Insufficient storage available. File can't be updated.");
            }
        }

        /// <summary>
        /// Unshares a file with all shared users on EnigmaEfs.
        /// </summary>
        /// <param name="pathOnEfs"></param>
        public void Unshare(string pathOnEfs)
        {
            var encryptedFile = new EncryptedFile(pathOnEfs.Substring(pathOnEfs.LastIndexOf('\\') + 1).Split('.')[0]);
            var updatedEncryptedFileRaw = encryptedFile.Unshare(File.ReadAllBytes(pathOnEfs), currentUser.Id);

            if (CanItBeStored(updatedEncryptedFileRaw.Length))
            {
                CreateFile(updatedEncryptedFileRaw, RootDir + "\\" + UserDir + "\\" + encryptedFile.GetEncryptedFileFullName());
                DeleteFile(pathOnEfs);
            }
            else
            {
                throw new Exception("Insufficient storage available. File can't be updated.");
            }
        }

        public List<int> GetSharedUsersId(int loggedInUserId, string pathOnEfs)
        {
            var encryptedFile = new EncryptedFile(pathOnEfs.Substring(pathOnEfs.LastIndexOf('\\') + 1).Split('.')[0]);
            encryptedFile.ParseEncryptedFile(File.ReadAllBytes(pathOnEfs));

            return encryptedFile.GetSharedUsersId(loggedInUserId);
        }

        /// <summary>
        /// Creates a new <em>.txt</em> file on EFS. File is first created in memory after which it's encrypted and stored on EFS.
        /// </summary>
        /// <param name="text">Content of the file.</param>
        /// <param name="pathOnEfs">Path on the encrypted file system where the file will be stored.</param>
        /// <param name="fileName">Name of the .txt file.</param>
        /// <param name="algorithmNameSignature">Name of the algorithm used for file encryption.</param>
        /// <param name="hashAlgorithmName">Name of the hashing algorithm used to create a file signature.</param>
        /// <returns>Encrypted name of the file.</returns>
        public string CreateTxtFile(string text, string pathOnEfs, string fileName, string algorithmNameSignature, string hashAlgorithmName)
        {
            return Upload(new OriginalFile(Encoding.ASCII.GetBytes(text), fileName + ".txt"), pathOnEfs, algorithmNameSignature, hashAlgorithmName);
        }

        /// <summary>
        /// Edits an existing <em>.txt</em> file on EFS by overwriting the original file.
        /// </summary>
        /// <param name="text">Content from the encrypted .txt file.</param>
        /// <param name="pathOnEfs">Path on the EFS where file is stored which includes files name.</param>
        public void EditTxtFile(string text, string pathOnEfs, string fileName)
        {
            Update(pathOnEfs, new OriginalFile(Encoding.ASCII.GetBytes(text), fileName + ".txt"));
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
        /// Deletes all files user has shared with others.
        /// </summary>
        /// <param name="path">Path to the shared folder.</param>
        public void DeleteUsersShareFiles(string path)
        {
            try
            {
                foreach (var filePath in Directory.GetFiles(path))
                {
                    if (currentUser.Id == GetFileOwnerId(filePath))
                    {
                        DeleteFile(filePath);
                    }
                }
                foreach (var newDir in Directory.GetDirectories(path))
                {
                    DeleteUsersShareFiles(newDir);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
            }
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
        /// Parses only 4 bytes of data that represents owner id. First 16 bytes are skipped, while the next 4 bytes are converted to an <see cref="int"/>.
        /// </summary>
        /// <param name="path">Full path to the file.</param>
        /// <returns>File's owner id.</returns>
        public int GetFileOwnerId(string path)
        {
            var ownerId = new byte[4];
            using var reader = new BinaryReader(new FileStream(path, FileMode.Open));
            reader.BaseStream.Seek(16, SeekOrigin.Begin);
            reader.Read(ownerId, 0, 4);
            return BitConverter.ToInt32(ownerId, 0);
        }

        /// <summary>
        /// Opens users encrypted file. File is first decrypted and stored as a temporary file in a <em>temporary folder</em> after which is opened in a default app for that file set on the computer. 
        /// </summary>
        /// <param name="pathOnEfs">The name of the encrypted file including files path and encrypted name with .at extension.</param>
        /// <param name="ownerPublicKey">Public RSA key from the file owner used to check files signature.</param>
        public void OpenFile(string pathOnEfs, RSAParameters ownerPublicKey)
        {
            var encryptedFile = new EncryptedFile(pathOnEfs.Substring(pathOnEfs.LastIndexOf('\\') + 1).Split('.')[0]);
            var originalFile = encryptedFile.Decrypt(File.ReadAllBytes(pathOnEfs), currentUser.Id, currentUser.PrivateKey, ownerPublicKey);

            var tempFilePath = Path.GetTempPath() + "Enigma-" + Guid.NewGuid().ToString() + "." + originalFile.FileExtension;

            if (CanItBeStored(originalFile.FileContent.Length, tempFilePath.Substring(0, 2)))
            {
                // create a temporary file
                CreateFile(originalFile.FileContent, tempFilePath);

                // override existing encrypted file
                var encryptedFileUpdated = encryptedFile.Flush();
                if (CanItBeStored(encryptedFileUpdated.Length, pathOnEfs.Substring(0, 2)))
                {
                    CreateFile(encryptedFileUpdated, pathOnEfs);
                }

                var startInfo = new ProcessStartInfo(tempFilePath);
                Process.Start(startInfo);
            }
            else
            {
                throw new Exception("Insufficient storage available. File can't be read.");
            }
        }

        /// <summary>
        /// Writes data to file system.
        /// </summary>
        /// <param name="data">Data in raw form.</param>
        /// <param name="path">Full path with a name of the file.</param>
        private void CreateFile(byte[] data, string path)
        {
            using var stream = new FileStream(path, FileMode.Create);
            using var writter = new BinaryWriter(stream);
            writter.Write(data);
        }

        /// <summary>
        /// Removes all temporary files created while reading encrypted files. This method is called when application is closed or when user logs out.
        /// </summary>
        public static void RemoveTempFiles()
        {
            var filesToDelete = Directory.GetFiles(Path.GetTempPath(), "Enigma-*");
            foreach (var fileName in filesToDelete)
            {
                try
                {
                    File.Delete(fileName);
                }
                catch (Exception)
                {
                }
            }
        }
    }
}
