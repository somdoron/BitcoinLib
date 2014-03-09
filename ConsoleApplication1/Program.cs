using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Bitcoin.Domain;

namespace ConsoleApplication1
{
    class Program
    {
        static void Main(string[] args)
        {
            var key = ExtendedKey.CreateMaster(HexUtility.StringToByteArray("000102030405060708090a0b0c0d0e0f"));

            var dKey = key.DeriveChild(0 | 0x80000000).DeriveChild(1 | 0x80000000);

            Console.WriteLine(dKey.SerializePrivateKey(true));

            Console.WriteLine("xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs");


            Console.WriteLine(dKey.SerliazePublicKey(true));

            Console.WriteLine("xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ");

            
            Console.ReadLine();
        }
    }
}
