using Enigma.Wpf.Enums;
using Enigma.Models;
using GalaSoft.MvvmLight;

namespace Enigma.Wpf.Observables
{
    /// <summary>
    /// Represents object's stored on Enigma EFS.
    /// </summary>
    public class FileSystemItem : ObservableObject
    {
        private string name;

        /// <summary>
        /// Object's name.
        /// </summary>
        public string Name
        {
            get => name;
            set => Set(() => Name, ref name, value);
        }

        /// <summary>
        /// Type of object stored on Engima EFS. It can be a file or directory.
        /// </summary>
        public FileSystemItemType Type { get; set; }

        /// <summary>
        /// File's object value.
        /// </summary>
        private readonly IEfsStorageObject efsObject;

        public FileSystemItem(IEfsStorageObject root, bool isItSharedRoot)
        {
            efsObject = root;

            if (root.DirFlag)
            {
                name = root.Name;
                if (isItSharedRoot == true)
                {
                    Type = FileSystemItemType.SharedFolder;
                }
                else
                {
                    Type = FileSystemItemType.Folder;
                }
            }
            else
            {
                Type = FileSystemItemType.File;
                if (((EfsFile)root).Name == null)
                {
                    name = ((EfsFile)root).EncryptedName;
                }
                else
                {
                    name = ((EfsFile)root).Name;
                }
            }
        }

        /// <summary>
        /// Checks if the user has access to the object.
        /// </summary>
        /// <returns>true if the user has access to the object, otherwise false.</returns>
        public bool IsAccessGranted()
        {
            return efsObject.Name != GetEncryptedFileName();
        }

        /// <summary>
        /// Gets file's encrypted name used in FS.
        /// </summary>
        /// <returns>File's encrypted name.</returns>
        public string GetEncryptedFileName()
        {
            return ((EfsFile)efsObject).EncryptedName;
        }

        /// <summary>
        /// Gets file's owner id.
        /// </summary>
        /// <returns>File's owner id.</returns>
        public int GetFileOwnerId()
        {
            return ((EfsFile)efsObject).OwnerId;
        }
    }
}
