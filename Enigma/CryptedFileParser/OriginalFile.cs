using System;

namespace Enigma.CryptedFileParser
{
    /// <summary>
    /// Represents unencrypted file.
    /// </summary>
    public class OriginalFile
    {
        /// <summary>
        /// Unencrypted file's raw data.
        /// </summary>
        public byte[] FileContent { get; internal set; }

        /// <summary>
        /// Unencrypted file's name.
        /// </summary>
        public string FileName { get; internal set; }

        /// <summary>
        /// Unencrypted file's size.
        /// </summary>
        public string FileExtension { get; internal set; }

        /// <summary>
        /// Size of the unencrypted file in bytes.
        /// </summary>
        public int FileSize => FileContent.Length;

        ///// <summary>
        ///// List of allowed file extensions.
        ///// </summary>
        //private readonly HashSet<string> allowedExtensions = new HashSet<string> { "txt", "docx", "doc", "png", "jpeg", "jpg", "pdf", "xlsx", "xls", "ppt", "pptx" };

        public OriginalFile(byte[] fileContent, string fileName)
        {
            //              0           1
            // tokens [ file_name, file_extension ]
            var tokens = fileName.Split('.');

            //if (ExtensionCheck(tokens[1]))
            //{
            FileContent = fileContent;
            FileName = tokens[0];
            FileExtension = tokens[1];
            //}
            //else
            //{
            //throw new Exception($"File type '{tokens[1]}' is not supported");
            //}
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
