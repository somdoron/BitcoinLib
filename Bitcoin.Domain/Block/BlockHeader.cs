using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Bitcoin.Common;
using Org.BouncyCastle.Math;

namespace Bitcoin.Domain.Block
{
    public class BlockHeader
    {
        public const int CurrentVersion = 2;

        private BigInteger m_hash;

        private int m_version;
        private BigInteger m_hashPrevBlock;
        BigInteger m_hashMerkleRoot;
        uint m_time;
        uint m_bits;
        uint m_nonce;

        public BlockHeader()
        {
            m_version = CurrentVersion;
            m_hashPrevBlock = BigInteger.Zero;
            m_hashMerkleRoot = BigInteger.Zero;
            m_time = 0;
            m_bits = 0;
            m_nonce = 0;
        }

        public bool IsNull
        {
            get
            {
                return m_bits == 0;
            }
        }

        public BigInteger Hash
        {
            get
            {
                if (m_hash == null || m_hash.CompareTo(BigInteger.Zero) == 0)
                {
                    using (MemoryStream memoryStream = new MemoryStream())
                    {
                        using (BinaryWriter binaryWriter = new BinaryWriter(memoryStream))
                        {
                            binaryWriter.WriteNetworkOrder(m_version);
                            binaryWriter.WriteNetworkOrder(m_version);
                            binaryWriter.Write(m_hashPrevBlock);
                            binaryWriter.Write(m_hashMerkleRoot);
                            binaryWriter.WriteNetworkOrder(m_bits);
                            binaryWriter.WriteNetworkOrder(m_nonce);
                        }

                        m_hash = HashUtility.DoubleSHA256(memoryStream.ToArray());
                    }
                }

                return m_hash;
            }
        }

    }
}
