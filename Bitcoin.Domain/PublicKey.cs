using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Bitcoin.Common;
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

        protected bool Equals(PublicKey other)
        {
            return Compressed.Equals(other.Compressed) && BytesUtility.CompareByteArray(Key, other.Key);
        }

        public override bool Equals(object obj)
        {
            if (ReferenceEquals(null, obj)) return false;
            if (ReferenceEquals(this, obj)) return true;
            if (obj.GetType() != this.GetType()) return false;
            return Equals((PublicKey) obj);
        }

        public override int GetHashCode()
        {
            int hash = Key.Length;

            for (int i = 0; i < Key.Length; i++)
            {
                hash ^= Key[i]*397;
            }

            return hash;
        }
    }
}
