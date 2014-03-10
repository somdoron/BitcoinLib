using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Org.BouncyCastle.Math;

namespace Bitcoin.Common
{
    public class HashUtility
    {
        public static BigInteger DoubleSHA256(byte[] bytes)
        {
            SHA256Managed sha256Managed = new SHA256Managed();
            var hash = sha256Managed.ComputeHash(bytes);
            hash = sha256Managed.ComputeHash(hash);

            return new BigInteger(hash);
        }    
    }
}
