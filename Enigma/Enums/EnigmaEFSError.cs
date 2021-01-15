namespace Enigma.Enums
{
    /// <summary>
    /// Represents different errors that can occur while using Enigma EFS.
    /// </summary>
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
