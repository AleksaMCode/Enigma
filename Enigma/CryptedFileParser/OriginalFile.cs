using System.IO;

namespace Enigma.CryptedFileParser
{
    public class OriginalFile
    {
        public Stream FileContent { get; internal set; }

        public string FileName { get; internal set; }

        public string FileExtension { get; internal set; }

        /// <summary>
        /// List of allowed file extensions.
        /// </summary>
        private readonly string[] allowedExtensions = { "txt", "docx", "png", "jpeg", "pdf" };

        public OriginalFile(Stream fileContent, string fileName)
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
                // throw an exception
            }
        }

        public bool ExtensionCheck(string fileExtension)
        {
            foreach (var extension in allowedExtensions)
            {
                if (fileExtension.Equals(extension))
                {
                    return true;
                }
            }
            return false;
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
