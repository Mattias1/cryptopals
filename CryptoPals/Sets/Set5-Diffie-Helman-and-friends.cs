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
            return runSet(33, challenge33, challenge34);
        }

        // MITM key-fixing attack on DH with parameter injection
        public static bool challenge34() {
            assertModExp();

            var alice = new DhServer();
            var bob = new DhServer();
            var eve = new DhServer();

            var initRequest = alice.InitiateDh(eve); // Haha, not bob, surprise!
            var (p, g, a) = initRequest;
            var initResponse = bob.ReceiveInitiationRequest(new DhInitiation(eve, bob, p, g, p));
            byte[] b = initResponse.PublicKey;
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
            byte[] key = ByteArrayHelpers.CopyPartOf(Sha1.Hash(BigInteger.Zero.ToByteArray()), 0, 16);
            byte[] interceptedPlain = BlockCipher.DecryptAES(messageRequest1.Message.Cipher, key, messageRequest1.Message.Iv, CipherMode.CBC, PaddingMode.PKCS7);
            string interceptedMessage = ConversionHelpers.ToUTF8String(interceptedPlain);

            Console.WriteLine("Intercepted message: {0}", interceptedMessage);
            return interceptedMessage == "Howdy Bob";
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
