using System;
using System.Linq;
using System.Numerics;
using System.Security.Cryptography;

namespace CryptoPals
{
    class Set5 : Set
    {
        // Run all challenges of set 5
        public static bool runSet5() {
            return runSet(33, challenge33, challenge34, challenge35);
        }

        // MITM attack on DH with negotiated groups - parameter injection on g
        public static bool challenge35() {
            bool result = true;

            // g = 1
            result &= mitmNegotiatedGroups(p => 1, (BigInteger p, BigInteger alicesPublicKey, BigInteger bobsPublicKey, DhMessage messageRequest) =>
            {
                // Key: s = g^a^b % p = 1^a^b % p = 1
                return intercepteDhMessage(messageRequest, BigInteger.One);
            });

            // g = p
            result &= mitmNegotiatedGroups(p => p, (BigInteger p, BigInteger alicesPublicKey, BigInteger bobsPublicKey, DhMessage messageRequest) =>
            {
                // Key: s = g^a^b % p = p^a^b % p = 0
                return intercepteDhMessage(messageRequest, BigInteger.Zero);
            });

            // g = p - 1
            result &= mitmNegotiatedGroups(p => p - 1, (BigInteger p, BigInteger alicesPublicKey, BigInteger bobsPublicKey, DhMessage messageRequest) =>
            {
                // Assume a and b are even:
                // Key: s = g^a^b % p = (p-1)^a^b % p = (p-1)^b % p = p-1

                // Assume a is even and b is odd:
                // Key: s = g^a^b % p = (p-1)^a^b % p = (p-1)^b % p = 1

                // Assume a is odd:
                // Key: s = g^a^b % p = (p-1)^a^b % p = 1^b = 1
                var key = alicesPublicKey.IsEven && bobsPublicKey.IsEven ? p - 1 : BigInteger.One;
                return intercepteDhMessage(messageRequest, key);
            });

            return result;
        }

        private static bool mitmNegotiatedGroups(Func<BigInteger, BigInteger> tamperG, Func<BigInteger, BigInteger, BigInteger, DhMessage, string> mitmFunc) {
            var alice = new DhServer();
            var bob = new DhServer();
            var eve = new DhServer();

            var initNegotiation = alice.InitiateDhNegotiation(eve);
            byte[] p = initNegotiation.P;
            byte[] g = tamperG(ConversionHelpers.ToBigInt(p)).ToByteArray();
            var negotiationResponse = bob.ReceiveDhNegotiationRequest(new DhNegotiation(eve, bob, p, g));
            var alicesPublicKey = alice.ReceiveDhNegotiationResponse(new DhNegotiation(eve, alice, p, g));
            var bobsPublicKey = bob.ReceiveDhNegotiatedPublicKey(new DhInitiationResponse(eve, bob, alicesPublicKey.PublicKey));
            alice.ReceiveDhFinalNegotiatedPublicKey(new DhInitiationResponse(eve, alice, bobsPublicKey.PublicKey));

            var messageRequest1 = alice.SendTextMessage(eve, "Ho Bob");
            string message1 = bob.ReceiveTextMessage(new DhMessage(eve, bob, messageRequest1.Message));

            var messageRequest2 = bob.SendTextMessage(eve, message1);
            string message2 = alice.ReceiveTextMessage(new DhMessage(eve, alice, messageRequest2.Message));

            if (message2 != "Ho Bob") {
                Console.WriteLine("But... but... Bob?");
                return false;
            }

            string interceptedMessage = mitmFunc(ConversionHelpers.ToBigInt(p), ConversionHelpers.ToBigInt(alicesPublicKey.PublicKey),
                ConversionHelpers.ToBigInt(bobsPublicKey.PublicKey), messageRequest1);

            Console.WriteLine("Intercepted message: {0}, with g: {1}", interceptedMessage, ConversionHelpers.ToHexString(g, true));
            if (interceptedMessage != "Ho Bob") {
                return false;
            }
            return true;
        }

        // MITM key-fixing attack on DH with parameter injection
        public static bool challenge34() {
            assertModExp();

            var alice = new DhServer();
            var bob = new DhServer();
            var eve = new DhServer();

            var initRequest = alice.InitiateDh(eve); // Haha, not bob, surprise!
            var (p, g, _) = initRequest;
            var initResponse = bob.ReceiveInitiationRequest(new DhInitiation(eve, bob, p, g, p));
            alice.ReceiveInitiationResponse(new DhInitiationResponse(eve, alice, p));

            var messageRequest1 = alice.SendTextMessage(eve, "Howdy Bob");
            string message1 = bob.ReceiveTextMessage(new DhMessage(eve, bob, messageRequest1.Message));

            var messageRequest2 = bob.SendTextMessage(eve, message1);
            string message2 = alice.ReceiveTextMessage(new DhMessage(eve, alice, messageRequest2.Message));

            if (message2 != "Howdy Bob") {
                Console.WriteLine("But... but... Bob?");
                return false;
            }

            // Normal: s = A^b % p = g^a^b % p
            // Now:    s = p^b % p = 0
            string interceptedMessage = intercepteDhMessage(messageRequest1, BigInteger.Zero);

            Console.WriteLine("Intercepted message: {0}", interceptedMessage);
            return interceptedMessage == "Howdy Bob";
        }

        private static string intercepteDhMessage(DhMessage messageRequest1, BigInteger sessionKey) {
            byte[] key = ByteArrayHelpers.CopyPartOf(Sha1.Hash(sessionKey.ToByteArray()), 0, 16);
            byte[] interceptedPlain = BlockCipher.DecryptAES(messageRequest1.Message.Cipher, key, messageRequest1.Message.Iv, CipherMode.CBC, PaddingMode.PKCS7);
            return ConversionHelpers.ToUTF8String(interceptedPlain);
        }

        // Implement Diffie-Helman
        public static bool challenge33() {
            assertModExp();

            KeyPair a = DiffieHelman.GenerateKeypair();
            KeyPair b = DiffieHelman.GenerateKeypair();

            byte[] s1 = DiffieHelman.GenerateSessionKey(a.PublicKey, b.PrivateKey);
            byte[] s2 = DiffieHelman.GenerateSessionKey(b.PublicKey, a.PrivateKey);

            if (!MiscHelpers.Equals(s1, s2)) {
                Console.WriteLine("Diffie helman keypair and sessionkey fail.");
                return false;
            }

            byte[] sessionKey = Sha1.Hash(s1);
            ConversionHelpers.PrintHexString("DH session key: ", sessionKey);

            return true;
        }

        private static void assertModExp() {
            uint fourteen = DiffieHelman.ModExp(5, 3, 37);
            uint twentythree = DiffieHelman.ModExp(5, 21, 37);
            uint zero = DiffieHelman.ModExp(23, 1, 23);

            if (fourteen != 14 || twentythree != 23 || zero != 0) {
                throw new Exception($"Diffie helman mod-exp fail: 14 vs {fourteen}, 23 vs {twentythree}, 0 vs {zero}");
            }
        }
    }
}
