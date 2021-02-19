using System;
using System.Collections.Generic;

namespace Enigma.CryptedFileParser
{
    public class OriginalFile
    {
        public byte[] FileContent { get; internal set; }

        public string FileName { get; internal set; }

        public string FileExtension { get; internal set; }

        public int FileSize => FileContent.Length;

        /// <summary>
        /// List of allowed file extensions.
        /// </summary>
        private readonly HashSet<string> allowedExtensions = new HashSet<string> { "txt", "docx", "doc", "png", "jpeg", "jpg", "pdf", "xlsx", "xls", "ppt", "pptx" };

        public OriginalFile(byte[] fileContent, string fileName)
        {
            // tokens[0] = file_name
            // tokens[1] = file_extension
            var tokens = fileName.Split('.');

            if (ExtensionCheck(tokens[1]))
            {
                FileContent = fileContent;
                FileName = tokens[0];
                FileExtension = tokens[1];
            }
            else
            {
                throw new Exception(string.Format("File type '{0}' is not supported", tokens[1]));
            }
        }

        /// <summary>
        /// Checks if the file extension is allowed.
        /// </summary>
        /// <param name="fileExtension">Extension of the file.</param>
        /// <returns>true if file type is permitted, otherwise false.</returns>
        public bool ExtensionCheck(string fileExtension)
        {
            return allowedExtensions.Contains(fileExtension);
        }

        /// <summary>
        /// Creates original files full name that contains file name and extension separated with '<b>.</b>'.
        /// </summary>
        /// <returns>Original file full name.</returns>
        public string GetOriginalFileFullName()
        {
            return FileName + "." + FileExtension;
        }
    }
}
