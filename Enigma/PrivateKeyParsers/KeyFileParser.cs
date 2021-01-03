using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace Enigma
{
    public class KeyFileParser
    {
        private const string PrivateHeaderStart = "-----BEGIN RSA PRIVATE KEY-----";


        private const string PrivateHeaderEnd = "-----END RSA PRIVATE KEY-----";


        private const string PrivateHeaderStartAlt = "-----BEGIN PRIVATE KEY-----";


        private const string PrivateHeaderEndAlt = "-----END PRIVATE KEY-----";


        private readonly byte[] rawParameters;


        private readonly bool isAlt = false;


        private readonly bool tryBoth = false;

        // TODO: add keyfile decryption

        public KeyFileParser(byte[] keyBytes)
        {
            byte[] trimmedBytes = Encoding.ASCII.GetBytes(Encoding.ASCII.GetString(keyBytes).Trim());

            if (trimmedBytes.Take(10).SequenceEqual(Encoding.ASCII.GetBytes("-----BEGIN")))
            {
                if (trimmedBytes.Take(PrivateHeaderStart.Length).SequenceEqual(Encoding.ASCII.GetBytes(PrivateHeaderStart)) &&
                    trimmedBytes.Skip(trimmedBytes.Length - PrivateHeaderEnd.Length).Take(PrivateHeaderEnd.Length).SequenceEqual(Encoding.ASCII.GetBytes(PrivateHeaderEnd)))
                {
                    this.rawParameters =
                        Convert.FromBase64String(
                            Encoding.ASCII.GetString(
                                trimmedBytes.Skip(PrivateHeaderStart.Length).Take(trimmedBytes.Length - PrivateHeaderStart.Length - PrivateHeaderEnd.Length - 1).ToArray()));
                    this.isAlt = false;
                }
                else if (trimmedBytes.Take(PrivateHeaderStartAlt.Length).SequenceEqual(Encoding.ASCII.GetBytes(PrivateHeaderStartAlt)) &&
                         trimmedBytes.Skip(trimmedBytes.Length - PrivateHeaderEndAlt.Length).Take(PrivateHeaderEndAlt.Length).SequenceEqual(Encoding.ASCII.GetBytes(PrivateHeaderEndAlt)))
                {
                    this.rawParameters =
                        Convert.FromBase64String(
                            Encoding.ASCII.GetString(
                                trimmedBytes.Skip(PrivateHeaderStartAlt.Length).Take(trimmedBytes.Length - PrivateHeaderStartAlt.Length - PrivateHeaderEndAlt.Length).ToArray()));
                    this.isAlt = true;
                }
                else
                {
                    throw new InvalidKeyFileException();
                }
            }
            else if (keyBytes[0] == 0x30)
            {
                this.tryBoth = true;
                this.rawParameters = keyBytes;
            }
            else
            {
                throw new InvalidKeyFileException();
            }
        }

        public RSAParameters GetParameters()
        {
            if (this.tryBoth)
            {
                try
                {
                    return this.GetParametersOriginal();
                }
                catch (InvalidKeyFileException)
                {
                }

                try
                {
                    return this.GetParametersAlt();
                }
                catch (InvalidKeyFileException)
                {
                }

                throw new InvalidKeyFileException();
            }
            else if (this.isAlt)
            {
                return this.GetParametersAlt();
            }
            else
            {
                return this.GetParametersOriginal();
            }
        }

        private RSAParameters GetParametersOriginal()
        {
            using (ASNPrivateKeyParser parser = new ASNPrivateKeyParser(this.rawParameters))
            {
                RSAParameters result = new RSAParameters();

                if (!parser.IsNextTag(0x30))
                {
                    throw new InvalidKeyFileException();
                }

                parser.EnterNextContent();

                var versionBytes = parser.GetNext(3);
                if (versionBytes.SequenceEqual(new byte[] { 0x02, 0x01, 0x00 }) == false)
                {
                    throw new InvalidKeyFileException();
                }

                result.Modulus = parser.GetNextContent();
                result.Exponent = parser.GetNextContent();
                result.D = parser.GetNextContent();
                result.P = parser.GetNextContent();
                result.Q = parser.GetNextContent();
                result.DP = parser.GetNextContent();
                result.DQ = parser.GetNextContent();
                result.InverseQ = parser.GetNextContent();

                return result;
            }
        }

        private RSAParameters GetParametersAlt()
        {
            using (ASNPrivateKeyParser parser = new ASNPrivateKeyParser(this.rawParameters))
            {
                RSAParameters result = new RSAParameters();

                if (!parser.IsNextTag(0x30))
                {
                    throw new InvalidKeyFileException();
                }

                parser.EnterNextContent();

                var versionBytes = parser.GetNext(3);
                if (versionBytes.SequenceEqual(new byte[] { 0x02, 0x01, 0x00 }) == false)
                {
                    throw new InvalidKeyFileException();
                }

                if (!parser.IsNextTag(0x30))
                {
                    throw new InvalidKeyFileException();
                }

                parser.EnterNextContent();

                if (!parser.IsNextTag(0x06))
                {
                    throw new InvalidKeyFileException();
                }

                var objectIdentifier = parser.GetNextContent();
                if (objectIdentifier.SequenceEqual(new byte[] { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01 }) == false)
                {
                    throw new InvalidKeyFileException();
                }

                var nullBytes = parser.GetNext(2);
                if (nullBytes[0] != 0x05 || nullBytes[1] != 0x0)
                {
                    throw new InvalidKeyFileException();
                }

                if (!parser.IsNextTag(0x04))
                {
                    throw new InvalidKeyFileException();
                }

                parser.EnterNextContent();

                if (!parser.IsNextTag(0x30))
                {
                    throw new InvalidKeyFileException();
                }

                parser.EnterNextContent();

                var versionBytes2 = parser.GetNext(3);
                if (versionBytes2.SequenceEqual(new byte[] { 0x02, 0x01, 0x00 }) == false)
                {
                    throw new InvalidKeyFileException();
                }

                result.Modulus = parser.GetNextContent();
                result.Exponent = parser.GetNextContent();
                result.D = parser.GetNextContent();
                result.P = parser.GetNextContent();
                result.Q = parser.GetNextContent();
                result.DP = parser.GetNextContent();
                result.DQ = parser.GetNextContent();
                result.InverseQ = parser.GetNextContent();

                return result;
            }
        }
    }
}