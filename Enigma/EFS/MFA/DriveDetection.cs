using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace Enigma.EFS.MFA
{
    /// <summary>
    /// Class is used to detect a new hardware RSA key used for MFA.
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
                nextDriveLetter--;
                return true;
            }
            else
            {
                return false;
            }
        }

        public async Task<byte[]> ReadDataFromDriveAsync(int timeOut)
        {
            var isTimedOut = false;
            await Task.Run(async () =>
            {
                var waitCounter = 0;
                while(!Directory.Exists(nextDriveLetter + ":"))
                {
                    await Task.Delay(500);
                    waitCounter++;
                    if(waitCounter >= 2*timeOut)
                    {
                        isTimedOut = true;
                        break;
                    }
                }
            });

            if (isTimedOut)
            {
                return null;
            }

            drives.Add(nextDriveLetter);

            // read a file to memory
            var path = nextDriveLetter + ":\\" + "key.bin";

            if (Directory.GetFiles(nextDriveLetter + ":").Length == 1)
            {
                path += ":\\" + "key.bin";

                var data = File.Exists(path)
                    ? File.ReadAllBytes(path)
                    : throw new Exception("Usb key has been compromised or wrong usb has been inserted.");

                SetNextDriveLetter();
                return data;
            }
            else
            {
                throw new Exception("Usb key has been compromised or wrong usb has been inserted.");
            }
        }
    }
}
