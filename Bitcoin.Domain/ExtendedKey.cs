using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.IO;
using System.Linq;
using System.Net.Mail;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.Tls;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Bitcoin.Domain
{
    public class ExtendedKey
    {
        private static readonly SecureRandom Random = new SecureRandom();
        private static readonly X9ECParameters Curve = SecNamedCurves.GetByName("secp256k1");

        private const string PreSeed = "Bitcoin seed";
        private const int SeedLength = 256;

        private PrivateKey m_privateKey;
        private PublicKey m_publicKey;
        private readonly byte[] m_chainCode;
        private readonly int m_depth;
        private readonly int m_parentFingerprint;
        private readonly uint m_sequence;

        public ExtendedKey(PrivateKey key, byte[] chainCode, int depth, int parentFingerprint, uint sequence)
        {
            m_privateKey = key;
            m_publicKey = key.PublicKey;
            m_chainCode = chainCode;
            m_depth = depth;
            m_parentFingerprint = parentFingerprint;
            m_sequence = sequence;
        }

        public ExtendedKey(PublicKey key, byte[] chainCode, int depth, int parentFingerprint, uint sequence)
        {
            m_publicKey = key;
            m_chainCode = chainCode;
            m_depth = depth;
            m_parentFingerprint = parentFingerprint;
            m_sequence = sequence;
        }



        private static void SplitToLeftRight(byte[] i, out byte[] il, out byte[] ir)
        {
            il = new byte[32];
            ir = new byte[32];

            Buffer.BlockCopy(i, 0, il, 0, 32);
            Buffer.BlockCopy(i, 32, ir, 0, 32);
        }

        public PrivateKey PrivateKey
        {
            get { return m_privateKey; }
        }

        public PublicKey PublicKey
        {
            get { return m_publicKey; }
        }

        public int Depth
        {
            get { return m_depth; }
        }

        public uint Sequence
        {
            get { return m_sequence; }
        }

        public int Fingerprint
        {
            get
            {
                int fingerprint = 0;
                byte[] address = m_publicKey.Identifier;

                for (int i = 0; i < 4; ++i)
                {
                    fingerprint <<= 8;
                    fingerprint |= address[i] & 0xff;
                }
                return fingerprint;
            }
        }

        public static ExtendedKey CreateMaster()
        {
            byte[] seed = new byte[SeedLength / 8];

            Random.NextBytes(seed);

            return CreateMaster(seed);
        }

        public static ExtendedKey CreateMaster(byte[] seed)
        {
            var hmac = new HMACSHA512(Encoding.ASCII.GetBytes(PreSeed));
            byte[] i = hmac.ComputeHash(seed);

            byte[] il;
            byte[] ir;

            SplitToLeftRight(i, out il, out ir);

            BigInteger bigInteger = new BigInteger(1,il);

            if (bigInteger.CompareTo(BigInteger.Zero) == 0 || bigInteger.CompareTo(Curve.N) >= 0)
            {
                throw new InvalidKeyException();
            }

            return new ExtendedKey(new PrivateKey(bigInteger, true), ir, 0, 0, 0);
        }

        public ExtendedKey DeriveChild(uint sequence)
        {
            bool generatePrivate = (sequence & 0x80000000) != 0;

            if (generatePrivate && m_privateKey == null)
            {
                throw new InvalidOperationException("cannot derive private key without private key");
            }

            HMACSHA512 hmacsha512 = new HMACSHA512(m_chainCode);
            byte[] data;

            if (generatePrivate)
            {
                // private key length + 4 for the sequence + 1
                data = new byte[m_privateKey.Length + 4 + 1];
                data[0] = 0;
                Buffer.BlockCopy(m_privateKey.ToBytes(), 0, data, 1, m_privateKey.Length);
                data[m_privateKey.Length + 1] = (byte)((sequence >> 24) & 0xff);
                data[m_privateKey.Length + 2] = (byte)((sequence >> 16) & 0xff);
                data[m_privateKey.Length + 3] = (byte)((sequence >> 8) & 0xff);
                data[m_privateKey.Length + 4] = (byte)(sequence & 0xff);
            }
            else
            {
                data = new byte[m_publicKey.Length + 4];
                Buffer.BlockCopy(m_publicKey.Key, 0, data, 0, m_publicKey.Length);

                data[m_publicKey.Length] = (byte)((sequence >> 24) & 0xff);
                data[m_publicKey.Length + 1] = (byte)((sequence >> 16) & 0xff);
                data[m_publicKey.Length + 2] = (byte)((sequence >> 8) & 0xff);
                data[m_publicKey.Length + 3] = (byte)(sequence & 0xff);
            }

            byte[] i = hmacsha512.ComputeHash(data);

            byte[] il;
            byte[] ir;
            SplitToLeftRight(i, out il, out ir);

            BigInteger m = new BigInteger(1, il);

            if (m.CompareTo(Curve.N) >= 0)
            {
                throw new InvalidKeyException();
            }

            if (generatePrivate)
            {
                BigInteger k = m.Add(new BigInteger(1, m_privateKey.ToBytes())).Mod(Curve.N);

                if (k.CompareTo(BigInteger.Zero) == 0)
                {
                    throw new InvalidKeyException();
                }

                PrivateKey privateKey = new PrivateKey(k, true);

                return new ExtendedKey(privateKey, ir, m_depth + 1, Fingerprint, sequence);
            }
            else
            {
                ECPoint q = Curve.G.Multiply(m).Add(Curve.Curve.DecodePoint(m_publicKey.Key));

                byte[] pubKeyBytes = new FpPoint(Curve.Curve, q.X, q.Y, true).GetEncoded();

                PublicKey publicKey = new PublicKey(pubKeyBytes, true);

                return new ExtendedKey(publicKey, ir, m_depth + 1, Fingerprint, sequence);
            }
        }

        private static readonly byte[] xprv = new byte[] { 0x04, (byte)0x88, (byte)0xAD, (byte)0xE4 };
        private static readonly byte[] xpub = new byte[] { 0x04, (byte)0x88, (byte)0xB2, (byte)0x1E };
        private static readonly byte[] tprv = new byte[] { 0x04, (byte)0x35, (byte)0x83, (byte)0x94 };
        private static readonly byte[] tpub = new byte[] { 0x04, (byte)0x35, (byte)0x87, (byte)0xCF };

        public string SerializePrivateKey(bool mainNet)
        {
            if (m_privateKey == null)
            {
                throw new InvalidOperationException("cannot serialize extended private key without private key");
            }

            return Serialize(true, mainNet);
        }

        public string SerliazePublicKey(bool mainNet)
        {
            return Serialize(false, mainNet);
        }

        private string Serialize(bool serailizePrivate, bool mainNet)
        {
            MemoryStream stream = new MemoryStream();

            if (mainNet)
            {
                if (serailizePrivate)
                {
                    stream.Write(xprv, 0, 4);
                }
                else
                {
                    stream.Write(xpub, 0, 4);
                }
            }
            else
            {
                if (serailizePrivate)
                {
                    stream.Write(tprv, 0, 4);
                }
                else
                {
                    stream.Write(tpub, 0, 4);
                }
            }

            stream.WriteByte((byte)(Depth & 0xff));
            stream.WriteByte((byte)((m_parentFingerprint >> 24) & 0xff));
            stream.WriteByte((byte)((m_parentFingerprint >> 16) & 0xff));
            stream.WriteByte((byte)((m_parentFingerprint >> 8) & 0xff));
            stream.WriteByte((byte)(m_parentFingerprint & 0xff));

            stream.WriteByte((byte)((Sequence >> 24) & 0xff));
            stream.WriteByte((byte)((Sequence >> 16) & 0xff));
            stream.WriteByte((byte)((Sequence >> 8) & 0xff));
            stream.WriteByte((byte)(Sequence & 0xff));
            stream.Write(m_chainCode, 0, m_chainCode.Length);

            if (serailizePrivate)
            {
                stream.WriteByte(0x00);
                stream.Write(m_privateKey.ToBytes(), 0, m_privateKey.Length);
            }
            else
            {
                stream.Write(m_publicKey.Key, 0, m_publicKey.Length);
            }

            return Base58Utility.ToBase58WithChecksum(stream.ToArray());
        }
    }
}
