using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;

namespace Bitcoin.Domain
{
    public class PrivateKey
    {
        private static readonly X9ECParameters Curve = SecNamedCurves.GetByName("secp256k1");

        private BigInteger m_key;
        private byte[] m_bytes;
        
        public PrivateKey(BigInteger key, bool compressed)
        {
            m_key = key;

            Compressed = compressed;
            m_bytes = new byte[32];

            byte[] p = key.ToByteArray();            

            Buffer.BlockCopy(p, Math.Max(0, p.Length - 32), m_bytes, Math.Max(0, 32 - p.Length), Math.Min(32, p.Length));
                                
            ECPoint q = Curve.G.Multiply(m_key);

            if (compressed)
            {
                byte[] pubKeyBytes = new FpPoint(Curve.Curve, q.X, q.Y, true).GetEncoded();
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
    }
}
