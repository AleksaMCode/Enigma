﻿using System;
using System.IO;

namespace Enigma
{
    public class OriginalFile
    {
        public Stream FileContent { get; internal set; }

        public string FileName { get; internal set; }

        public string FileExtension { get; internal set; }

        /// <summary>
        /// List of allowed file extensions.
        /// </summary>
        private string[] allowedExtensions = { "txt", "docx", "png", "jpeg", "pdf" };

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