using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Math;

namespace Bitcoin.Common
{
    public static class BytesUtility
    {
        private static readonly char[] Base58Chars;
        private static readonly int[] CharToBase58;

        static BytesUtility()
        {
            Base58Chars = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".ToCharArray();

            CharToBase58 = new int[256];

            for (int i = 0; i < 256; i++)
            {
                CharToBase58[i] = -1;
            }

            for (int i = 0; i < Base58Chars.Length; ++i)
            {
                CharToBase58[Base58Chars[i]] = i;
            }
        }

        public static byte[] HexStringToByteArray(string hex)
        {
            return Enumerable.Range(0, hex.Length)
                .Where(x => x % 2 == 0)
                .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                .ToArray();
        }

        public static string ByteArrayToHexString(byte[] bytes)
        {
            return BitConverter.ToString(bytes).Replace("-", "");
        }

        public static string ToBase58(byte[] b)
        {
            if (b.Length == 0)
            {
                return "";
            }

            int lz = 0;
            while (lz < b.Length && b[lz] == 0)
            {
                ++lz;
            }

            StringBuilder s = new StringBuilder();
            BigInteger n = new BigInteger(1, b);
            while (n.CompareTo(BigInteger.Zero) > 0)
            {
                BigInteger[] r = n.DivideAndRemainder(BigInteger.ValueOf(58));
                n = r[0];
                char digit = Base58Chars[r[1].IntValue];
                s.Append(digit);
            }
            while (lz > 0)
            {
                --lz;
                s.Append("1");
            }

            return new string(s.ToString().Reverse().ToArray());
        }

        public static byte[] Checksum(byte[] b, int offset, int count, int checksumSize)
        {
            SHA256Managed sha256 = new SHA256Managed();

            byte[] hash = sha256.ComputeHash(b, offset, count);
            sha256.Initialize();
            hash = sha256.ComputeHash(hash);

            byte[] cs = new byte[checksumSize];
            Buffer.BlockCopy(hash, 0, cs, 0, checksumSize);

            return hash;
        }

        public static byte[] Checksum(byte[] b, int checksumSize)
        {
            return Checksum(b, 0, b.Length, checksumSize);
        }

        public static String ToBase58WithChecksum(byte[] b)
        {
            byte[] cs = Checksum(b,4);

            byte[] extended = new byte[b.Length + 4];
            Buffer.BlockCopy(b, 0, extended, 0, b.Length);
            Buffer.BlockCopy(cs, 0, extended, b.Length, 4);

            return ToBase58(extended);
        }

        public static byte[] FromBase58(String s)
        {
            bool leading = true;
            int lz = 0;
            BigInteger b = BigInteger.Zero;
            foreach (char c in s)
            {
                if (leading && c == '1')
                {
                    ++lz;
                }
                else
                {
                    leading = false;
                    b = b.Multiply(BigInteger.ValueOf(58));
                    b = b.Add(BigInteger.ValueOf(CharToBase58[c]));
                }
            }
            byte[] encoded = b.ToByteArray();
            if (encoded[0] == 0)
            {
                if (lz > 0)
                {
                    --lz;
                }
                else
                {
                    byte[] e = new byte[encoded.Length - 1];
                    Buffer.BlockCopy(encoded, 1, e, 0, e.Length);
                    encoded = e;
                }
            }

            byte[] result = new byte[encoded.Length + lz];
            Buffer.BlockCopy(encoded, 0, result, lz, encoded.Length);

            return result;
        }

        public static byte[] FromBase58WithChecksum(String s)
        {
            byte[] b = FromBase58(s);
            if (b.Length < 4)
            {
                throw new InvalidOperationException("Too short for checksum " + s);
            }
            
            byte[] checksum = Checksum(b, 0, b.Length - 4, 4);

            int checksumIndex = b.Length - 4;

            for (int i = 0; i < 4; i++)
            {
                if (checksum[i] != b[checksumIndex + i])
                    throw new InvalidOperationException("Checksum mismatch " + s);                
            }                       

            byte[] data = new byte[b.Length - 4];
            Buffer.BlockCopy(b, 0, data, 0, b.Length - 4);

            return data;
        }

        public static bool CompareByteArray(byte[] a, byte[] b)
        {
            if (a.Length != b.Length)
                return false;

            for (int i = 0; i < a.Length; i++)
            {
                if (a[i] != b[i])
                    return false;                
            }

            return true;
        }

    }
}
