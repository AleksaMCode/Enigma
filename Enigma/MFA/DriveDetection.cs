using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace Enigma
{
    /// <summary>
    /// Class is used to detect a new hardware RSA key and OTP used for MFA and account recovery.
    /// </summary>
    public class DriveDetection
    {
        private readonly HashSet<char> drives = null;
        public char nextDriveLetter { get; set; } = '0';

        public DriveDetection()
        {
            drives = DriveInfo.GetDrives().Select(drive => drive.Name[0]).ToHashSet<char>();
            nextDriveLetter = drives.ElementAt(0);
            SetNextDriveLetter();
        }

        private void SetNextDriveLetter()
        {
            while (drives.Contains(nextDriveLetter))
            {
                nextDriveLetter++;
            }
        }

        public bool EjectDriveLetter()
        {
            if (drives.Remove(nextDriveLetter))
            {
                nextDriveLetter = '0';
                return true;
            }
            else
            {
                return false;
            }
        }

        public bool ReadDataFromDrive(ref byte[] data)
        {
            while (!Directory.Exists(nextDriveLetter + ":"))
            {
                ;
            }

            if (Directory.Exists(nextDriveLetter + ":"))
            {
                // read a file to memory
                if (File.Exists("*.at"))
                {

                }
                else
                {
                    return false;
                }
            }

            return false;
        }
    }
}
