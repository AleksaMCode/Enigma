using System;
using System.IO;

namespace Enigma
{
    public class OriginalFile
    {
        public Stream FileContent { get; internal set; }

        public string FileExtension { get; internal set; }

        /// <summary>
        /// List of allowed file extensions.
        /// </summary>
        private string[] allowedExtensions = { "txt", "docx", "png", "jpeg", "pdf" };

        public OriginalFile(Stream fileContent, string fileExtension)
        {
            ExtensionCheck(fileExtension);
            FileContent = fileContent;
            FileExtension = fileExtension;
        }

        public bool ExtensionCheck(string fileExtension)
        {
            foreach(string extension in allowedExtensions)
            {
                if(fileExtension.Equals(extension))
                {
                    return true;
                }
            }
            return false;
        }
    }
}