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
    //public class HashUtility
    //{
    //    public static byte[] DoubleHashTwoBuffers(byte[] buffer1, byte[] buffer2)
    //    {
    //        SHA256Managed sha256Managed = new SHA256Managed();
    //        sha256Managed.TransformBlock(buffer1, 0, buffer1.Length, buffer1, 0);
    //        sha256Managed.TransformFinalBlock(buffer2, 0, buffer2.Length);

    //        byte[] hash = sha256Managed.Hash;
    //        return sha256Managed.ComputeHash(hash);
    //    }

    //    public static byte[] DoubleHash(byte[] bytes)
    //    {
    //        SHA256Managed sha256Managed = new SHA256Managed();
    //        var hash = sha256Managed.ComputeHash(bytes);
    //        hash = sha256Managed.ComputeHash(hash);

    //        return hash;
    //    }    
    //}
}
