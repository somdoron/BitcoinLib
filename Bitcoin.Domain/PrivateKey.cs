using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Bitcoin.Common;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;

namespace Bitcoin.Domain
{
    public class PrivateKey
    {        
        private BigInteger m_key;
        private byte[] m_bytes;
        
        public PrivateKey(BigInteger key, bool compressed)
        {
            m_key = key;

            Compressed = compressed;
            m_bytes = new byte[32];

            byte[] p = key.ToByteArray();            

            Buffer.BlockCopy(p, Math.Max(0, p.Length - 32), m_bytes, Math.Max(0, 32 - p.Length), Math.Min(32, p.Length));

            ECPoint q = EllipticCurve.G.Multiply(m_key);

            if (compressed)
            {
                byte[] pubKeyBytes = new FpPoint(EllipticCurve.Curve, q.X, q.Y, true).GetEncoded();
                PublicKey = new PublicKey(pubKeyBytes, true);
            }
            else
            {
                PublicKey = new PublicKey(q.GetEncoded(), false);
            }
        }

        public bool Compressed { get; private set; }

        public int Length
        {
            get
            {
                return m_bytes.Length;
            }
        }

        public byte[] ToBytes()
        {
            return m_bytes;
        }

        public PublicKey PublicKey
        {
            get;
            private set;
        }

        protected bool Equals(PrivateKey other)
        {
            return m_key.CompareTo(other.m_key) == 0 && Compressed.Equals(other.Compressed);
        }

        public override bool Equals(object obj)
        {
            if (ReferenceEquals(null, obj)) return false;
            if (ReferenceEquals(this, obj)) return true;
            if (obj.GetType() != this.GetType()) return false;
            return Equals((PrivateKey) obj);
        }

        public override int GetHashCode()
        {
            unchecked
            {
                return ((m_key != null ? m_key.GetHashCode() : 0)*397) ^ Compressed.GetHashCode();
            }
        }
    }
}
