using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;

namespace Enigma.Models
{
    /// <summary>
    /// Represents Enigma's EFS directories.
    /// </summary>
    public class EfsDirectory : IEfsStorageObject
    {
        public bool DirFlag { get; } = true;

        public string Name { get; set; }

        /// <summary>
        /// List of encrypted files and EFS directories.
        /// </summary>
        public List<IEfsStorageObject> objects = new List<IEfsStorageObject>();

        /// <summary>
        /// Initializes a new instance of the <see cref="EfsDirectory"/> class using specified parameters.
        /// </summary>
        /// <param name="path">Full path of the directory.</param>
        /// <param name="userId">Unique identifier of the logged-in user.</param>
        /// <param name="userPrivateKey">Users private RSA key.</param>
        public EfsDirectory(string path, int userId, RSAParameters userPrivateKey)
        {
            Name = path.Substring(path.LastIndexOf('\\') + 1);
            DirectorySearch(path, userId, userPrivateKey);
        }

        /// <summary>
        /// Initializes the list of objects <see cref="objects"/>.
        /// </summary>
        /// <param name="path">Full path of the directory.</param>
        /// <param name="userId">Unique identifier of the logged-in user.</param>
        /// <param name="userPrivateKey">Users private RSA key.</param>
        private void DirectorySearch(string path, int userId, RSAParameters userPrivateKey)
        {
            if (Directory.Exists(path))
            {
                foreach (var file in Directory.GetFiles(path))
                {
                    // only encrypted files can be added to the list
                    if (file.Split('.')[1].Equals("at"))
                    {
                        var fileRaw = File.ReadAllBytes(file);
                        if (fileRaw.Length != 0)
                        {
                            try
                            {
                                var newFile = new EfsFile(Path.GetFileName(file), fileRaw, userId, userPrivateKey);
                                objects.Add(newFile);
                            }
                            catch (Exception)
                            {
                            }

                        }
                    }
                }
                foreach (var dir in Directory.GetDirectories(path))
                {
                    objects.Add(new EfsDirectory(path + "\\" + Path.GetFileName(dir), userId, userPrivateKey));
                }
            }
            else
            {
                throw new Exception($"Path is '{path}' is missing.");
            }
        }
    }
}
