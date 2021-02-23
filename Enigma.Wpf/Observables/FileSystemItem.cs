using Enigma.Wpf.Enums;
using Enigma.Models;
using GalaSoft.MvvmLight;

namespace Enigma.Wpf.Observables
{
    public class FileSystemItem : ObservableObject
    {
        private string name;

        public string Name
        {
            get => name;
            set => Set(() => Name, ref name, value);
        }

        public FileSystemItemType Type { get; set; }

        private IEfsStorageObject efsObject;

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

        public bool IsAccessGranted()
        {
            return efsObject.Name != GetEncryptedFileName();
        }

        public string GetEncryptedFileName()
        {
            return ((EfsFile)efsObject).EncryptedName;
        }

        public int GetFileOwnerId()
        {
            return ((EfsFile)efsObject).OwnerId;
        }
    }
}
