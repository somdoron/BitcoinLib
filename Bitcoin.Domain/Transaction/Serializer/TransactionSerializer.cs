using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Bitcoin.Common;

namespace Bitcoin.Domain.Transaction.Serializer
{
    public class TransactionSerializer
    {
        private readonly TransactionInputSerializer m_inputSerializer = new TransactionInputSerializer();
        private readonly TransactionOutputSerializer m_outputSerializer = new TransactionOutputSerializer();

        public void Serialize(Stream stream, Transaction transaction)
        {
            using (BinaryWriter binaryWriter = new BinaryWriter(stream, Encoding.ASCII, true))
            {
                binaryWriter.WriteNetworkOrder(transaction.Version);

                binaryWriter.WriteVarInt(transaction.In.Count);

                foreach (TransactionInput transactionInput in transaction.In)
                {
                    m_inputSerializer.Serialize(stream, transactionInput);
                }

                binaryWriter.WriteVarInt(transaction.Out.Count);

                foreach (TransactionOutput transactionOutput in transaction.Out)
                {
                    m_outputSerializer.Serialize(stream, transactionOutput);
                }

                binaryWriter.WriteNetworkOrder(transaction.LockTime);
            }
        }

        public ImmutableByteArray Serialize(Transaction transaction)
        {
            using (MemoryStream memoryStream = new MemoryStream())
            {
                Serialize(memoryStream, transaction);

                return memoryStream.ToByteArray();
            }
        }
    }
}
