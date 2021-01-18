using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;

namespace Enigma.Models
{
    public class EfsDirectory : IEfsStorageObject
    {
        public bool DirFlag { get; } = true;

        public string Name { get; set; }

        public List<IEfsStorageObject> objects = new List<IEfsStorageObject>();

        public EfsDirectory(string path, int userId, RSAParameters userPrivateKey)
        {
            Name = path.Substring(path.LastIndexOf('\\') + 1);
            DirectorySearch(path, userId, userPrivateKey);
        }

        public void DirectorySearch(string path, int userId, RSAParameters userPrivateKey)
        {
            foreach (var file in Directory.GetFiles(path))
            {
                objects.Add(new EfsFile(Path.GetFileName(file), File.ReadAllBytes(file), userId, userPrivateKey));
            }
            foreach (var dir in Directory.GetDirectories(path))
            {
                objects.Add(new EfsDirectory(path + "\\" + Path.GetFileName(dir), userId, userPrivateKey));
            }
        }
    }
}
