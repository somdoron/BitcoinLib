using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Utilities.Net;
using IPAddress = System.Net.IPAddress;

namespace Bitcoin.Common
{
    public static class BinaryExtensions
    {
        public static void WriteNetworkOrder(this BinaryWriter writer, int value)
        {
            int fixedValue = IPAddress.HostToNetworkOrder(value);

            writer.Write(fixedValue);
        }

        public static int ReadInt32NetworkOrder(this BinaryReader reader)
        {
            int value = reader.ReadInt32();
            return IPAddress.NetworkToHostOrder(value);
        }

        public static void WriteNetworkOrder(this BinaryWriter writer, uint value)
        {
            UInt32 fixedValue = value;

            if (BitConverter.IsLittleEndian)
            {
                fixedValue = ReverseUInt(value);
            }

            writer.Write(fixedValue);
        }

        public static uint ReadUInt32NetworkOrder(this BinaryReader reader)
        {
            uint value = reader.ReadUInt32();

            if (BitConverter.IsLittleEndian)
            {
                value = ReverseUInt(value);
            }

            return value;
        }

        private static uint ReverseUInt(uint value)
        {
            return (value & 0x000000FFU) << 24 | (value & 0x0000FF00U) << 8 |
                       (value & 0x00FF0000U) >> 8 | (value & 0xFF000000U) >> 24;
        }

        public static void Write(this BinaryWriter writer, BigInteger value, bool reversed = true)
        {
            byte[] bytes = value.ToByteArray();

            if (reversed)
                Array.Reverse(bytes);

            writer.Write(value.ToByteArray());
        }
    }
}
