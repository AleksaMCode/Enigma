using System;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using Enigma.Enums;

namespace Enigma.Models
{
    public static class PasswordAdvisor
    {
        /// <summary>
        /// 8-character minimum length is a NIST requirement.
        /// </summary>
        private static readonly int minimumLength = 8;

        /// <summary>
        /// NIST requires maximum password length to be at least 64 characters.
        /// </summary>
        private static readonly int maximumLength = 200;

        /// <summary>
        /// Number of symbols in a symbol set. Used to calculate password entropy.
        /// </summary>
        public enum PasswordPoolSize
        {
            ArabicNumbers = 10,
            CaseInsensitiveLatinLetters = 26,
            CaseInsensitiveAlphanumeric = 36,
            CaseSensitiveLatinLetters = 52,
            CaseSensitiveAlphanumeric = 62,
            AsciiPrintableChars = 95,
            NonAlphanumericChars = AsciiPrintableChars - CaseSensitiveAlphanumeric,
            DicewareWordList = 7776
        }

        public static bool CommonPasswordCheck(string password, string commonPasswordsPath)
        {
            string commonPassword;
            var bufferSize = 4_096; // cluster size in NTFS = 4,096 b; this buffer size gave me best speed performance

            using var fileStream = File.OpenRead(commonPasswordsPath);
            using var streamReader = new StreamReader(fileStream, Encoding.ASCII, true, bufferSize);

            while ((commonPassword = streamReader.ReadLine()) != null)
            {
                if (commonPassword.Equals(password))
                {
                    return true;
                }
            }

            return false;
        }

        public static bool IsPasswordStrong(string password, out string passwordStrength, bool wordListGenerated = false, int numberOfWordsGenerated = 0)
        {
            // Memorized secrets SHALL be at least 8 characters in length not including spaces.
            if (string.Concat(password.Where(c => !char.IsWhiteSpace(c))).Length < minimumLength)
            {
                throw new Exception("Password must be at least 8 characters long not including the spaces.");
            }
            else if (password.Length > maximumLength)
            {
                throw new Exception("Password is too long.");
            }

            switch (GetPasswordEntropy(password, wordListGenerated, numberOfWordsGenerated))
            {
                //case PasswordEntropy.VeryWeak:
                //{
                //    passwordStrength = "Very Weak";
                //    return false;
                //}
                case PasswordEntropy.Weak:
                {
                    passwordStrength = "Weak";
                    return false;
                }
                case PasswordEntropy.Reasonable:
                {
                    passwordStrength = "Reasonable";
                    return true;
                }
                case PasswordEntropy.Strong:
                {
                    passwordStrength = "Strong";
                    return true;
                }
                case PasswordEntropy.VeryStrong:
                {
                    passwordStrength = "VeryStrong";
                    return true;
                }
                default:
                {
                    passwordStrength = "Very Weak";
                    return false;
                }
            }
        }

        private static PasswordEntropy GetPasswordEntropy(string password, bool wordListGenerated, int numberOfWordsGenerated = 0)
        {
            var entropy = CalculateEntropy(password, wordListGenerated, numberOfWordsGenerated);

            if (entropy <= 30)
            {
                return PasswordEntropy.VeryWeak;
            }
            else if (entropy > 30 && entropy <= 40)
            {
                return PasswordEntropy.Weak;
            }
            else if (entropy > 40 && entropy <= 60)
            {
                return PasswordEntropy.Reasonable;
            }
            else if (entropy > 60 && entropy <= 90)
            {
                return PasswordEntropy.Strong;
            }
            else // if (entropy > 90)
            {
                return PasswordEntropy.VeryStrong;
            }
        }

        private static double CalculateEntropy(string password, bool wordListGenerated, int numberOfWordsGenerated = 0)
        {
            if (wordListGenerated == true)
            {
                return Math.Log(Math.Pow((int)PasswordPoolSize.DicewareWordList, numberOfWordsGenerated), 2);
            }

            var passwordLength = password.Length;
            var lowerCaseCount = LowerCaseCount(password);
            var upperCaseCount = UpperCaseCount(password);
            var numericCount = NumericCount(password);
            var nonAlphaCount = NonAlphaCount(password);

            // All ASCII printable characters
            if (lowerCaseCount > 0 && upperCaseCount > 0 && numericCount > 0 && nonAlphaCount > 0)
            {
                return Math.Log(Math.Pow((int)PasswordPoolSize.AsciiPrintableChars, passwordLength), 2);
            }
            // Case sensitive alphanumeric (a–z, A–Z, 0–9) 
            else if (lowerCaseCount > 0 && upperCaseCount > 0 && numericCount > 0 && nonAlphaCount == 0)
            {
                return Math.Log(Math.Pow((int)PasswordPoolSize.CaseSensitiveAlphanumeric, passwordLength), 2);
            }
            // Case sensitive Latin alphabet (a–z, A–Z) + NonAlphaChars
            else if (lowerCaseCount > 0 && upperCaseCount > 0 && numericCount == 0 && nonAlphaCount > 0)
            {
                return Math.Log(Math.Pow((int)PasswordPoolSize.CaseSensitiveLatinLetters + (int)PasswordPoolSize.NonAlphanumericChars, passwordLength), 2);
            }
            // Case sensitive Latin alphabet (a–z, A–Z)
            else if (lowerCaseCount > 0 && upperCaseCount > 0 && numericCount == 0 && nonAlphaCount == 0)
            {
                return Math.Log(Math.Pow((int)PasswordPoolSize.CaseSensitiveLatinLetters, passwordLength), 2);
            }
            // Case insensitive Latin alphabet (a–z or A–Z) 	
            else if ((lowerCaseCount == 0 || upperCaseCount == 0) && numericCount == 0 && nonAlphaCount == 0)
            {
                return Math.Log(Math.Pow((int)PasswordPoolSize.CaseInsensitiveLatinLetters, passwordLength), 2);
            }
            // Case insensitive alphanumeric (a–z or A–Z, 0–9)
            else if ((lowerCaseCount == 0 || upperCaseCount == 0) && numericCount > 0 && nonAlphaCount == 0)
            {
                return Math.Log(Math.Pow((int)PasswordPoolSize.CaseInsensitiveAlphanumeric, passwordLength), 2);
            }
            // Case insensitive alphanumeric (a–z or A–Z, 0–9) + NonAlphaChars
            else if ((lowerCaseCount == 0 || upperCaseCount == 0) && numericCount == 0 && nonAlphaCount > 0)
            {
                return Math.Log(Math.Pow((int)PasswordPoolSize.CaseInsensitiveLatinLetters + (int)PasswordPoolSize.NonAlphanumericChars, passwordLength), 2);
            }
            // Case insensitive alphanumeric (a–z or A–Z, 0–9) + Arabic numerals (0–9) + NonAlphaChars
            else if ((lowerCaseCount == 0 || upperCaseCount == 0) && numericCount > 0 && nonAlphaCount > 0)
            {
                return Math.Log(Math.Pow((int)PasswordPoolSize.CaseInsensitiveLatinLetters + (int)PasswordPoolSize.ArabicNumbers + (int)PasswordPoolSize.NonAlphanumericChars, passwordLength), 2);
            }
            // Arabic numerals (0–9) + NonAlphaChars
            else if (lowerCaseCount == 0 && upperCaseCount == 0 && numericCount > 0 && nonAlphaCount > 0)
            {
                return Math.Log(Math.Pow((int)PasswordPoolSize.ArabicNumbers + (int)PasswordPoolSize.NonAlphanumericChars, passwordLength), 2);
            }
            // Arabic numerals (0–9)
            else if (numericCount == passwordLength)
            {
                return Math.Log(Math.Pow((int)PasswordPoolSize.ArabicNumbers, passwordLength), 2);
            }
            else // if (nonAlphaCount == passwordLength)
            {
                return Math.Log(Math.Pow((int)PasswordPoolSize.NonAlphanumericChars, passwordLength), 2);
            }
        }

        private static int UpperCaseCount(string password)
        {
            return Regex.Matches(password, "[A-Z]").Count;
        }

        private static int LowerCaseCount(string password)
        {
            return Regex.Matches(password, "[a-z]").Count;
        }

        private static int NumericCount(string password)
        {
            return Regex.Matches(password, "[0-9]").Count;
        }

        private static int NonAlphaCount(string password)
        {
            return Regex.Matches(password, @"[^0-9a-zA-Z]").Count;
        }
    }
}
