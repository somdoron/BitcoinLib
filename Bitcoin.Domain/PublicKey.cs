using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;

namespace Bitcoin.Domain
{
    public class PublicKey
    {

        public PublicKey(byte[] key, bool compressed)
        {
            Key = key;
            Compressed = compressed;
        }

        public int Length
        {
            get
            {
                return Key.Length;
            }
        }

        public bool Compressed
        {
            get;
            private set;
        }

        public byte[] Key
        {
            get;
            private set;
        }

        public byte[] Identifier
        {
            get
            {
                SHA256 sha256 = new SHA256Managed();
                byte[] hash = sha256.ComputeHash(Key);
                RIPEMD160 ripemd160 = new RIPEMD160Managed();
                return ripemd160.ComputeHash(hash);
            }
        }
    }
}
