using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;

namespace Bitcoin.Common
{
    public static class EllipticCurve
    {
        public static readonly X9ECParameters Parameters = SecNamedCurves.GetByName("secp256k1");

        public static ECCurve Curve
        {
            get
            {
                return Parameters.Curve;
            }
        }

        public static ECPoint G
        {
            get
            {
                return Parameters.G;
            }
        }

        public static BigInteger N
        {
            get
            {
                return Parameters.N;
            }
        }

        public static BigInteger H
        {
            get
            {
                return Parameters.H;
            }
        }
    }
}
