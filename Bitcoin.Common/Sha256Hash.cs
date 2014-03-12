using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Bitcoin.Common
{
    public class Sha256Hash : IEquatable<Sha256Hash>
    {
        private readonly ImmutableByteArray m_hash;

        public Sha256Hash(ImmutableByteArray hash)
        {
            if (hash.Length != 32)
            {
                throw new ArgumentException();
            }

            m_hash = hash;
        }

        public Sha256Hash(byte[] hash)
            : this(new ImmutableByteArray(hash))
        {

        }

        public static readonly Sha256Hash ZeroHash = new Sha256Hash(new byte[32]);

        public ImmutableByteArray ByteArray
        {
            get
            {
                return m_hash;
            }
        }

        public static Sha256Hash Hash(ImmutableByteArray buffer)
        {
            SHA256Managed sha256Managed = new SHA256Managed();
            byte[] hash = sha256Managed.ComputeHash(buffer.ToByteArray());

            return new Sha256Hash(hash);
        }

        public static Sha256Hash DoubleHash(ImmutableByteArray buffer)
        {
            SHA256Managed sha256Managed = new SHA256Managed();
            byte[] hash = sha256Managed.ComputeHash(buffer.ToByteArray());
            hash = sha256Managed.ComputeHash(hash);

            return new Sha256Hash(hash);
        }

        public static Sha256Hash DoubleHash(ImmutableByteArray buffer1, ImmutableByteArray buffer2)
        {
            SHA256Managed sha256Managed = new SHA256Managed();
            sha256Managed.TransformBlock(buffer1.ToByteArray(), 0, buffer1.Length, buffer1.ToByteArray(), 0);
            sha256Managed.TransformFinalBlock(buffer2.ToByteArray(), 0, buffer2.Length);

            byte[] hash = sha256Managed.Hash;
            hash = sha256Managed.ComputeHash(hash);

            return new Sha256Hash(hash);
        }

        public bool Equals(Sha256Hash other)
        {
            if (ReferenceEquals(null, other)) return false;
            if (ReferenceEquals(this, other)) return true;
            return m_hash.Equals(other.m_hash);
        }

        public override bool Equals(object obj)
        {
            if (ReferenceEquals(null, obj)) return false;
            if (ReferenceEquals(this, obj)) return true;
            if (obj.GetType() != this.GetType()) return false;
            return Equals((Sha256Hash) obj);
        }

        public override int GetHashCode()
        {
            return m_hash.GetHashCode();
        }

        public static bool operator ==(Sha256Hash left, Sha256Hash right)
        {
            return Equals(left, right);
        }

        public static bool operator !=(Sha256Hash left, Sha256Hash right)
        {
            return !Equals(left, right);
        }
    }
}
