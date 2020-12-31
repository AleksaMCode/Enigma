using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Enigma.Enums
{ 
    public enum EnigmaEFSError
    {
        MountLocationDoesntExist,
        DriveNotFound,
        DirectoryNotFound,
        InsufficientStorageAvailable,
        WrongFileType,
        FilePermission
    }
}
