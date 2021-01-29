using System.ComponentModel.DataAnnotations;
using System.IO;

namespace Enigma.Wpf.Attributes.Validation
{
    /// <summary>
    /// Custom ValidationAttribute class that is used for determining if string contains a path to existing file.
    /// </summary>
    public class FileExists : ValidationAttribute
    {
        private readonly bool invert;

        public FileExists()
        {
        }

        public FileExists(bool invert)
        {
            this.invert = invert;
        }

        public override bool IsValid(object value)
        {
            var strValue = value as string;

            if (value is null)
            {
                return true;
            }

            var res = File.Exists(strValue);

            return invert ? !res : res;
        }
    }
}
