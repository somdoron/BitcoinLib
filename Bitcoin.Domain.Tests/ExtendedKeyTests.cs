using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Permissions;
using System.Text;
using System.Threading.Tasks;
using Xunit;

namespace Bitcoin.Domain.Tests
{
    public class ExtendedKeyTests
    {
        [Fact]
        public void TestVector1()
        {
            ExtendedKey key = ExtendedKey.CreateMaster("000102030405060708090a0b0c0d0e0f");

            Assert.Equal(key.SerliazePublicKey(true), "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8");
            Assert.Equal(key.SerializePrivateKey(true), "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi");

            key = key.PrivateDerivation(0); // m/0'

            Assert.Equal(key.SerliazePublicKey(true), "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw");
            Assert.Equal(key.SerializePrivateKey(true), "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7");

            key = key.PublicDerivation(1); // m/0'/1

            Assert.Equal(key.SerliazePublicKey(true), "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ");
            Assert.Equal(key.SerializePrivateKey(true), "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs");

            key = key.PrivateDerivation(2); // m/0'/1/2'

            Assert.Equal(key.SerliazePublicKey(true), "xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5");
            Assert.Equal(key.SerializePrivateKey(true), "xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM");

            key = key.PublicDerivation(2); // m/0'/1/2'/2

            Assert.Equal(key.SerliazePublicKey(true), "xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV");
            Assert.Equal(key.SerializePrivateKey(true), "xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334");

            key = key.PublicDerivation(1000000000); // m/0'/1/2'/2/1000000000

            Assert.Equal(key.SerliazePublicKey(true), "xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy");
            Assert.Equal(key.SerializePrivateKey(true), "xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76");    
        }

        [Fact]
        public void TestVector2()
        {
            ExtendedKey key = ExtendedKey.CreateMaster("fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542");

            Assert.Equal(key.SerliazePublicKey(true), "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB");
            Assert.Equal(key.SerializePrivateKey(true), "xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U");

            key = key.PublicDerivation(0); // m/0

            Assert.Equal(key.SerliazePublicKey(true), "xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH");
            Assert.Equal(key.SerializePrivateKey(true), "xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt");

            key = key.PrivateDerivation(2147483647); // m/0/2147483647'

            Assert.Equal(key.SerliazePublicKey(true), "xpub6ASAVgeehLbnwdqV6UKMHVzgqAG8Gr6riv3Fxxpj8ksbH9ebxaEyBLZ85ySDhKiLDBrQSARLq1uNRts8RuJiHjaDMBU4Zn9h8LZNnBC5y4a");
            Assert.Equal(key.SerializePrivateKey(true), "xprv9wSp6B7kry3Vj9m1zSnLvN3xH8RdsPP1Mh7fAaR7aRLcQMKTR2vidYEeEg2mUCTAwCd6vnxVrcjfy2kRgVsFawNzmjuHc2YmYRmagcEPdU9");

            key = key.PublicDerivation(1); // m/0/2147483647'/1

            Assert.Equal(key.SerliazePublicKey(true), "xpub6DF8uhdarytz3FWdA8TvFSvvAh8dP3283MY7p2V4SeE2wyWmG5mg5EwVvmdMVCQcoNJxGoWaU9DCWh89LojfZ537wTfunKau47EL2dhHKon");
            Assert.Equal(key.SerializePrivateKey(true), "xprv9zFnWC6h2cLgpmSA46vutJzBcfJ8yaJGg8cX1e5StJh45BBciYTRXSd25UEPVuesF9yog62tGAQtHjXajPPdbRCHuWS6T8XA2ECKADdw4Ef");

            key = key.PrivateDerivation(2147483646); // m/0/2147483647'/1/2147483646'

            Assert.Equal(key.SerliazePublicKey(true), "xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL");
            Assert.Equal(key.SerializePrivateKey(true), "xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc");

            key = key.PublicDerivation(2); // m/0/2147483647'/1/2147483646'/2

            Assert.Equal(key.SerliazePublicKey(true), "xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLFbdpq8p9HmGsApME5hQTZ3emM2rnY5agb9rXpVGyy3bdW6EEgAtqt");
            Assert.Equal(key.SerializePrivateKey(true), "xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j");    
        }

        [Fact]
        public void DeriveFromPublicKey()
        {
            ExtendedKey extendedPrivateKey = 
                ExtendedKey.CreateMaster("fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542");
            ExtendedKey extendedPublicKey = ExtendedKey.Deserialze(extendedPrivateKey.SerliazePublicKey(true), true);

            ExtendedKey key = extendedPublicKey.PublicDerivation(0); // m/0

            Assert.Equal(key.SerliazePublicKey(true), "xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH");
        }

        [Fact]
        public void DeserializePrivateKey()
        {
            ExtendedKey key = ExtendedKey.CreateMaster("000102030405060708090a0b0c0d0e0f");
            
            string privateKeySerialized = key.SerializePrivateKey(true);

            ExtendedKey deserializedKey = ExtendedKey.Deserialze(privateKeySerialized, true);

            Assert.Equal(deserializedKey, key);           
        }
        
        [Fact]
        public void DeserializePublicKey()
        {
            ExtendedKey key = ExtendedKey.CreateMaster("000102030405060708090a0b0c0d0e0f");

            string publicKeySerialized = key.SerliazePublicKey(true);

            ExtendedKey deserializedKey = ExtendedKey.Deserialze(publicKeySerialized, true);

            Assert.Equal(deserializedKey.HasPrivateKey, false);
            Assert.Equal(deserializedKey.PublicKey, key.PublicKey);
            Assert.Equal(deserializedKey.Depth, key.Depth);
            Assert.Equal(deserializedKey.Fingerprint, key.Fingerprint);
            Assert.Equal(deserializedKey.Sequence, key.Sequence);
        }

        [Fact]
        public void DeserializeChild()
        {
            ExtendedKey extendedPrivateKey =
               ExtendedKey.CreateMaster("fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542");

            ExtendedKey key = extendedPrivateKey.PublicDerivation(1); // m/1

            string serializedKey = key.SerializePrivateKey(true);

            ExtendedKey deserializedKey = ExtendedKey.Deserialze(serializedKey, true);

            Assert.Equal(deserializedKey, key);
        }
    }
}
