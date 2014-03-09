using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Org.BouncyCastle.Math;

namespace Bitcoin.Domain
{
    public static class Base58Utility
    {
        private static readonly char[] b58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".ToCharArray();
        private static readonly int[] r58 = new int[256];

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
                char digit = b58[r[1].IntValue];
                s.Append(digit);
            }
            while (lz > 0)
            {
                --lz;
                s.Append("1");
            }

            return new string(s.ToString().Reverse().ToArray());
        }

        public static String ToBase58WithChecksum(byte[] b)
        {
            SHA256Managed sha256 = new SHA256Managed();

            byte[] cs = sha256.ComputeHash(b);
            sha256.Initialize();
            cs = sha256.ComputeHash(cs);

            byte[] extended = new byte[b.Length + 4];
            Buffer.BlockCopy(b, 0, extended,0, b.Length);
            Buffer.BlockCopy(cs, 0, extended, b.Length, 4);

            
            return ToBase58(extended);
        }
    }
}
