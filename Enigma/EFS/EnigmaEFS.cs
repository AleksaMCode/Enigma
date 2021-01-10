using System.IO;

namespace Enigma
{
    /// <summary>
    /// Allows to create, modify or manipulate an Enigma Encripted File System.
    /// </summary>
    public class EnigmaEFS
    {
        private readonly string mountLocation = @"D:";
        private readonly string rootDir = @"D:\EnigmaEFS";
        private readonly string sharedDir = @"D:\EnigmaEFS\Shared";
        public long AvailableFreeSpace { get; set; }
        public EnigmaEFS()
        {
            // EFS "mount"
            if (Directory.Exists(mountLocation))
            {
                // create a new root directory if one isn't already created
                if (!Directory.Exists(mountLocation))
                {
                    Directory.CreateDirectory(rootDir);
                }
                // create a new shared directory if one isn't already created
                else if (Directory.Exists(mountLocation) && !Directory.Exists(mountLocation))
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
    }
}
