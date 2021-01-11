using System;
using System.IO;
using System.Linq;
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
        /// Used to calculate password entropy.
        /// </summary>
        public enum PasswordPoolSize
        {
            Numbers = 10,
            LowerOrUpperCaseLatinLetters = 26,
            LowerAndUpperCaseLatinLetter = 52,
            LowerAndUpperCaseLatinLetterAndNumbers = 62,
            AsciiPrintableChars = 95,
            EFFWordList = 7776
        }

        public static bool CommonPasswordCheck(string password)
        {
            string commonPassword;
            var file = new StreamReader(@"C:\Users\Aleksa\source\repos\Enigma\Enigma\10-million-password-list-top-1000000.txt");

            while ((commonPassword = file.ReadLine()) != null)
            {
                if (commonPassword.Equals(password))
                {
                    return false;
                }
            }

            return true;
        }

        public static bool IsPasswordStrong(string password, bool wordListGenerated = false, int numberOfWordsGenerated = 0)
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
                case PasswordEntropy.VeryWeak:
                case PasswordEntropy.Weak:
                {
                    return false;
                }
                case PasswordEntropy.Reasonable:
                case PasswordEntropy.Strong:
                case PasswordEntropy.VeryStrong:
                {
                    return true;
                }
                default:
                {
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
                return Math.Log(Math.Pow((int)PasswordPoolSize.EFFWordList, numberOfWordsGenerated), 2);
            }

            var passwordLength = password.Length;
            var lowerCaseCount = LowerCaseCount(password);
            var upperCaseCount = UpperCaseCount(password);
            var numericCount = NumericCount(password);
            var nonAlphaCount = NonAlphaCount(password);

            // AsciiPrintableChars
            if (lowerCaseCount > 0 && upperCaseCount > 0 && numericCount > 0 && nonAlphaCount > 0)
            {
                return Math.Log(Math.Pow((int)PasswordPoolSize.AsciiPrintableChars, passwordLength), 2);
            }
            // LowerAndUpperCaseLatinLetterAndNumbers + Numbers
            else if (lowerCaseCount > 0 && upperCaseCount > 0 && numericCount > 0 && nonAlphaCount == 0)
            {
                return Math.Log(Math.Pow((int)PasswordPoolSize.LowerAndUpperCaseLatinLetterAndNumbers, passwordLength), 2);
            }
            // LowerAndUpperCaseLatinLetterAndNumbers + NonAlphaChars
            else if (lowerCaseCount > 0 && upperCaseCount > 0 && numericCount == 0 && nonAlphaCount > 0)
            {
                return Math.Log(Math.Pow((int)PasswordPoolSize.LowerAndUpperCaseLatinLetter +
                    ((int)PasswordPoolSize.AsciiPrintableChars - (int)PasswordPoolSize.LowerAndUpperCaseLatinLetterAndNumbers), passwordLength), 2);
            }
            // LowerAndUpperCaseLatin
            else if (lowerCaseCount > 0 && upperCaseCount > 0 && numericCount == 0 && nonAlphaCount == 0)
            {
                return Math.Log(Math.Pow((int)PasswordPoolSize.LowerAndUpperCaseLatinLetter, passwordLength), 2);
            }
            // LowerOrUpperCaseLatinLetters
            else if ((lowerCaseCount == 0 || upperCaseCount == 0) && numericCount == 0 && nonAlphaCount == 0)
            {
                return Math.Log(Math.Pow((int)PasswordPoolSize.LowerOrUpperCaseLatinLetters, passwordLength), 2);
            }
            // LowerOrUpperCaseLatinLetters + Numbers
            else if ((lowerCaseCount == 0 || upperCaseCount == 0) && numericCount > 0 && nonAlphaCount == 0)
            {
                return Math.Log(Math.Pow((int)PasswordPoolSize.LowerOrUpperCaseLatinLetters + (int)PasswordPoolSize.Numbers, passwordLength), 2);
            }
            // LowerOrUpperCaseLatinLetters + nonAlphaChars
            else if ((lowerCaseCount == 0 || upperCaseCount == 0) && numericCount == 0 && nonAlphaCount > 0)
            {
                return Math.Log(Math.Pow((int)PasswordPoolSize.LowerOrUpperCaseLatinLetters +
                    ((int)PasswordPoolSize.AsciiPrintableChars - (int)PasswordPoolSize.LowerAndUpperCaseLatinLetterAndNumbers), passwordLength), 2);
            }
            // LowerOrUpperCaseLatinLetters + Numbers + NonAlphaChars
            else if ((lowerCaseCount == 0 || upperCaseCount == 0) && numericCount > 0 && nonAlphaCount > 0)
            {
                return Math.Log(Math.Pow((int)PasswordPoolSize.LowerOrUpperCaseLatinLetters +
                    (int)PasswordPoolSize.Numbers +
                    ((int)PasswordPoolSize.AsciiPrintableChars - (int)PasswordPoolSize.LowerAndUpperCaseLatinLetterAndNumbers), passwordLength), 2);
            }
            // Numbers + NonAlphaChars
            else if (lowerCaseCount == 0 && upperCaseCount == 0 && numericCount > 0 && nonAlphaCount > 0)
            {
                return Math.Log(Math.Pow((int)PasswordPoolSize.Numbers + ((int)PasswordPoolSize.AsciiPrintableChars -
                    (int)PasswordPoolSize.LowerAndUpperCaseLatinLetterAndNumbers), passwordLength), 2);
            }
            else if (numericCount == passwordLength)
            {
                return Math.Log(Math.Pow((int)PasswordPoolSize.Numbers, passwordLength), 2);
            }
            else // if (nonAlphaCount == passwordLength)
            {
                return Math.Log(Math.Pow((int)PasswordPoolSize.AsciiPrintableChars -
                    (int)PasswordPoolSize.LowerAndUpperCaseLatinLetterAndNumbers, passwordLength), 2);
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
