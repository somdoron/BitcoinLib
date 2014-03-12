using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Bitcoin.Common;
using Bitcoin.Domain.Transaction;
using Org.BouncyCastle.Math;

namespace Bitcoin.Domain.Block
{
    public class Block : IBlockHeader
    {
        private IList<Sha256Hash> m_merkleTree;
        private IList<Transaction.Transaction> m_transactions; 

        public const int CurrentVersion = 2;

        public Block()
        {             
            m_transactions = new List<Transaction.Transaction>();
            m_merkleTree = new List<Sha256Hash>();

            MerkleTree = new ReadOnlyCollection<Sha256Hash>(m_merkleTree);
            Transactions = new ReadOnlyCollection<Transaction.Transaction>(m_transactions);

            Version = CurrentVersion;
            PrevBlockHash = null;
            MerkleRootHash = null;
            Time = 0;
            Bits = 0;
            Nonce = 0;                            
        }

        public int Version { get; set; }

        public Sha256Hash PrevBlockHash { get; set; }        

        public uint Time { get; set; }

        public uint Bits { get; set; }

        public uint Nonce { get; set; }

        public Sha256Hash Hash { get; private set; }

        public Sha256Hash MerkleRootHash { get; private set; }

        public IReadOnlyList<Sha256Hash> MerkleTree { get; private set; } 

        public IReadOnlyList<Transaction.Transaction> Transactions { get; private set; }

        public void AddTransaction(Transaction.Transaction transaction)
        {
            m_transactions.Add(transaction);
        }

        public void RemoveTransaction(Transaction.Transaction transaction)
        {
            m_transactions.Remove(transaction);
        }

        public void BuildHash()
        {
            using (MemoryStream memoryStream = new MemoryStream())
            {
                using (BinaryWriter binaryWriter = new BinaryWriter(memoryStream))
                {
                    binaryWriter.WriteNetworkOrder(Version);
                    binaryWriter.Write(PrevBlockHash);
                    binaryWriter.Write(MerkleRootHash);
                    binaryWriter.WriteNetworkOrder(Time);
                    binaryWriter.WriteNetworkOrder(Bits);
                    binaryWriter.WriteNetworkOrder(Nonce);
                }

                Hash = Sha256Hash.DoubleHash(memoryStream.ToByteArray());
            }
        }

        public void BuildMerkleTree()
        {
            m_merkleTree.Clear();

            foreach (Transaction.Transaction transaction in Transactions)
            {
                m_merkleTree.Add(transaction.Hash);
            }

            // Offset in the list where the currently processed level starts.
            var levelOffset = 0; 
            
            // Step through each level, stopping when we reach the root (levelSize == 1).
            for (var levelSize = Transactions.Count; levelSize > 1; levelSize = (levelSize + 1) / 2)
            {
                // For each pair of nodes on that level:
                for (var left = 0; left < levelSize; left += 2)
                {
                    // The right hand node can be the same as the left hand, in the case where we don't have enough
                    // transactions.

                    var right = Math.Min(left + 1, levelSize - 1);
                    
                    var leftBytes = m_merkleTree[levelOffset + left];
                    var rightBytes = m_merkleTree[levelOffset + right];

                    var hash = Sha256Hash.DoubleHash(leftBytes.ByteArray, rightBytes.ByteArray);

                    m_merkleTree.Add(hash);                                            
                }
                // Move to the next level.
                levelOffset += levelSize;
            }

            MerkleRootHash = m_merkleTree.Last();
        }          
    }
}
