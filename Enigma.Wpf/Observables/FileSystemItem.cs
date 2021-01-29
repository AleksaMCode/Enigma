using Enigma.Enums;
using Enigma.Models;
using GalaSoft.MvvmLight;

namespace Enigma.Observables
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

        public FileSystemItem(IEfsStorageObject root)
        {
            efsObject = root;

            if (root.DirFlag)
            {
                name = root.Name;
                Type = FileSystemItemType.Folder;
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

            Type = FileSystemItemType.Folder;
        }

        public bool AccessGranted()
        {
            return efsObject.Name == null ? false : true;
        }
    }
}
