using System;
using System.Linq;
using System.Security.Cryptography;

namespace CryptoPals
{
    class Set5 : Set
    {
        // Run all challenges of set 5
        public static bool runSet5() {
            return runSet(33, challenge33);
        }

        // Implement Diffie-Helman
        public static bool challenge33() {
            AssertModExp();

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

        private static void AssertModExp() {
            uint fourteen = DiffieHelman.ModExp(5, 3, 37);
            uint twentythree = DiffieHelman.ModExp(5, 21, 37);

            if (fourteen != 14 || twentythree != 23) {
                throw new Exception($"Diffie helman mod-exp fail: 14 vs {fourteen}, 23 vs {twentythree}");
            }
        }
    }
}
