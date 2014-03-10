using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.IO;
using System.Linq;
using System.Net.Mail;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Bitcoin.Common;
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
        
        private static readonly byte[] VersionMainNetPrivate = new byte[] { 0x04, 0x88, 0xAD, 0xE4 };
        private static readonly byte[] VersionMainNetPublic = new byte[] { 0x04, 0x88, 0xB2, (byte)0x1E };
        private static readonly byte[] VersionTestNetPrivate = new byte[] { 0x04, 0x35, 0x83, (byte)0x94 };
        private static readonly byte[] VersionTestNetPublic = new byte[] { 0x04, 0x35, 0x87, (byte)0xCF };

        private const string PreSeed = "Bitcoin seed";
        private const int SeedLength = 256;

        private readonly byte[] m_chainCode;
        private readonly int m_parentFingerprint;

        private ExtendedKey(PrivateKey key, byte[] chainCode, int depth, int parentFingerprint, uint sequence)
        {
            PrivateKey = key;
            PublicKey = key.PublicKey;
            m_chainCode = chainCode;
            Depth = depth;
            m_parentFingerprint = parentFingerprint;
            Sequence = sequence;
        }

        private ExtendedKey(PublicKey key, byte[] chainCode, int depth, int parentFingerprint, uint sequence)
        {
            PublicKey = key;
            m_chainCode = chainCode;
            Depth = depth;
            m_parentFingerprint = parentFingerprint;
            Sequence = sequence;
        }

        private static void SplitToLeftRight(byte[] i, out byte[] il, out byte[] ir)
        {
            il = new byte[32];
            ir = new byte[32];

            Buffer.BlockCopy(i, 0, il, 0, 32);
            Buffer.BlockCopy(i, 32, ir, 0, 32);
        }

        public PrivateKey PrivateKey { get; private set; }

        public PublicKey PublicKey { get; private set; }

        public int Depth { get; private set; }

        public uint Sequence { get; private set; }

        public bool HasPrivateKey
        {
            get
            {
                return PrivateKey != null;
            }
        }

        public int Fingerprint
        {
            get
            {
                int fingerprint = 0;
                byte[] address = PublicKey.Identifier;

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

        public static ExtendedKey CreateMaster(string hexSeed)
        {
            return CreateMaster(BytesUtility.HexStringToByteArray(hexSeed));
        }

        public static ExtendedKey CreateMaster(byte[] seed)
        {
            var hmac = new HMACSHA512(Encoding.ASCII.GetBytes(PreSeed));
            byte[] i = hmac.ComputeHash(seed);

            byte[] il;
            byte[] ir;

            SplitToLeftRight(i, out il, out ir);

            BigInteger bigInteger = new BigInteger(1, il);

            if (bigInteger.CompareTo(BigInteger.Zero) == 0 || bigInteger.CompareTo(EllipticCurve.N) >= 0)
            {
                throw new InvalidKeyException();
            }

            return new ExtendedKey(new PrivateKey(bigInteger, true), ir, 0, 0, 0);
        }

        public ExtendedKey PrivateDerivation(uint sequence)
        {
            return Derive(sequence | 0x80000000);
        }

        public ExtendedKey PublicDerivation(uint sequence)
        {
            if ((sequence & 0x80000000) != 0)
            {
                throw new InvalidOperationException("cannot do public derivation when the MSB is set");
            }

            return Derive(sequence);
        }

        public ExtendedKey Derive(uint sequence)
        {
            bool privateDerivation = (sequence & 0x80000000) != 0;

            if (privateDerivation && !HasPrivateKey)
            {
                throw new InvalidOperationException("cannot do private derivation without private key");
            }            

            HMACSHA512 hmacsha512 = new HMACSHA512(m_chainCode);
            byte[] data;

            if (privateDerivation)
            {                
                data = new byte[PrivateKey.Length + 4 + 1];
                data[0] = 0;
                Buffer.BlockCopy(PrivateKey.ToBytes(), 0, data, 1, PrivateKey.Length);
                data[PrivateKey.Length + 1] = (byte)((sequence >> 24) & 0xff);
                data[PrivateKey.Length + 2] = (byte)((sequence >> 16) & 0xff);
                data[PrivateKey.Length + 3] = (byte)((sequence >> 8) & 0xff);
                data[PrivateKey.Length + 4] = (byte)(sequence & 0xff);
            }
            else
            {
                data = new byte[PublicKey.Length + 4];
                Buffer.BlockCopy(PublicKey.Key, 0, data, 0, PublicKey.Length);

                data[PublicKey.Length] = (byte)((sequence >> 24) & 0xff);
                data[PublicKey.Length + 1] = (byte)((sequence >> 16) & 0xff);
                data[PublicKey.Length + 2] = (byte)((sequence >> 8) & 0xff);
                data[PublicKey.Length + 3] = (byte)(sequence & 0xff);
            }

            byte[] i = hmacsha512.ComputeHash(data);

            byte[] il;
            byte[] ir;
            SplitToLeftRight(i, out il, out ir);

            BigInteger m = new BigInteger(1, il);

            if (m.CompareTo(EllipticCurve.N) >= 0)
            {
                throw new InvalidKeyException();
            }

            if (HasPrivateKey)
            {
                BigInteger k = m.Add(new BigInteger(1, PrivateKey.ToBytes())).Mod(EllipticCurve.N);

                if (k.CompareTo(BigInteger.Zero) == 0)
                {
                    throw new InvalidKeyException();
                }

                PrivateKey privateKey = new PrivateKey(k, true);

                return new ExtendedKey(privateKey, ir, Depth + 1, Fingerprint, sequence);
            }
            else
            {
                ECPoint q = EllipticCurve.G.Multiply(m).Add(EllipticCurve.Curve.DecodePoint(PublicKey.Key));

                if (q.IsInfinity)
                {
                    throw new InvalidKeyException();
                }

                byte[] pubKeyBytes = new FpPoint(EllipticCurve.Curve, q.X, q.Y, true).GetEncoded();

                PublicKey publicKey = new PublicKey(pubKeyBytes, true);

                return new ExtendedKey(publicKey, ir, Depth + 1, Fingerprint, sequence);
            }
        }           

        public string SerializePrivateKey(bool mainNet)
        {
            if (!HasPrivateKey)
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
            using (MemoryStream stream = new MemoryStream())
            {
                using (BinaryWriter binaryWriter = new BinaryWriter(stream))
                {
                    if (mainNet)
                    {
                        if (serailizePrivate)
                        {
                            binaryWriter.Write(VersionMainNetPrivate);
                        }
                        else
                        {
                            binaryWriter.Write(VersionMainNetPublic);
                        }
                    }
                    else
                    {
                        if (serailizePrivate)
                        {
                            binaryWriter.Write(VersionTestNetPrivate);
                        }
                        else
                        {
                            binaryWriter.Write(VersionTestNetPublic);
                        }
                    }

                    binaryWriter.Write((byte) (Depth & 0xff));
                    binaryWriter.WriteNetworkOrder(m_parentFingerprint);
                    binaryWriter.WriteNetworkOrder(Sequence);                                        
                    binaryWriter.Write(m_chainCode);

                    if (serailizePrivate)
                    {
                        binaryWriter.Write((byte) 0x00);
                        binaryWriter.Write(PrivateKey.ToBytes());
                    }
                    else
                    {
                        binaryWriter.Write(PublicKey.Key);
                    }
                }

                return BytesUtility.ToBase58WithChecksum(stream.ToArray());
            }
        }

        public static ExtendedKey Deserialze(string serializedKey, bool mainnet)
        {
            using (Stream stream = new MemoryStream(BytesUtility.FromBase58WithChecksum(serializedKey)))
            {
                using (BinaryReader binaryReader = new BinaryReader(stream))
                {
                    bool isMainnet;
                    bool isPrivateKey;

                    byte[] version = binaryReader.ReadBytes(4);

                    if (BytesUtility.CompareByteArray(version, VersionMainNetPrivate))
                    {
                        isMainnet = true;
                        isPrivateKey = true;
                    }
                    else if (BytesUtility.CompareByteArray(version, VersionMainNetPublic))
                    {
                        isMainnet = true;
                        isPrivateKey = false;
                    }
                    else if (BytesUtility.CompareByteArray(version, VersionTestNetPrivate))
                    {
                        isMainnet = false;
                        isPrivateKey = true;
                    }
                    else if (BytesUtility.CompareByteArray(version, VersionTestNetPublic))
                    {
                        isMainnet = false;
                        isPrivateKey = false;
                    }
                    else
                    {
                        throw new InvalidOperationException("unknown version");
                    }

                    if (isMainnet != mainnet)
                    {
                        throw new InvalidOperationException("version is not mathing the net (test/main)");
                    }

                    byte depth = binaryReader.ReadByte();

                    int parentFingerprint = binaryReader.ReadInt32NetworkOrder();
                    uint sequence = binaryReader.ReadUInt32NetworkOrder();

                    byte[] chainCode = binaryReader.ReadBytes(32);
                    byte[] key = binaryReader.ReadBytes(33);                    

                    if (isPrivateKey)
                    {
                        PrivateKey privateKey = new PrivateKey(new BigInteger(1, key, 1, 32), true);
                        return new ExtendedKey(privateKey, chainCode, depth, parentFingerprint, sequence);
                    }
                    else
                    {
                        PublicKey publicKey = new PublicKey(key, true);
                        return new ExtendedKey(publicKey, chainCode, depth, parentFingerprint, sequence);
                    }                    
                }
            }
        }

        protected bool Equals(ExtendedKey other)
        {
            return BytesUtility.CompareByteArray(m_chainCode, other.m_chainCode) && 
                Equals(PrivateKey, other.PrivateKey) && 
                m_parentFingerprint == other.m_parentFingerprint && 
                Depth == other.Depth && 
                Sequence == other.Sequence && 
                Equals(PublicKey, other.PublicKey);
        }

        public override bool Equals(object obj)
        {
            if (ReferenceEquals(null, obj)) return false;
            if (ReferenceEquals(this, obj)) return true;
            if (obj.GetType() != this.GetType()) return false;
            return Equals((ExtendedKey) obj);
        }

        public override int GetHashCode()
        {
            unchecked
            {
                int hashCode = (m_chainCode != null ? m_chainCode.GetHashCode() : 0);
                hashCode = (hashCode*397) ^ (PrivateKey != null ? PrivateKey.GetHashCode() : 0);
                hashCode = (hashCode*397) ^ m_parentFingerprint;
                hashCode = (hashCode*397) ^ Depth;
                hashCode = (hashCode*397) ^ (int) Sequence;
                hashCode = (hashCode*397) ^ (PublicKey != null ? PublicKey.GetHashCode() : 0);
                return hashCode;
            }
        }
    }
}
