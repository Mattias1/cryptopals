using System.Collections.Generic;

namespace CryptoPals
{
    public static class Md4
    {
        public const int ChunkSize = 64;

        public static Dictionary<string, string> KnownHashes {
            get {
                return new Dictionary<string, string>
                {
                    {"", "31d6cfe0d16ae931b73c59d7e0c089c0"},
                    {"a", "bde52cb31de33e46245e05fbdbd6fb24"},
                    {"abc", "a448017aaf21d8525fc10ae87aa6729d"},
                    {"message digest", "d9130a8164549fe818874806e1c7014b"},
                    {"abcdefghijklmnopqrstuvwxyz", "d79e1c308aa5bbcdeea8ed63df412da9"},
                    {"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "043f8582f241db351ce627e153e7f0e4"},
                    {"12345678901234567890123456789012345678901234567890123456789012345678901234567890", "e33b4ddc9c38f2199c3e7b164fcc0536"}
                };
            }
        }

        public static string Hash(string message) {
            return ConversionHelpers.ToHexString(Hash(ConversionHelpers.FromUTF8String(message)), false);
        }
        public static byte[] Hash(byte[] message) {
            uint[] hash = { 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476 };
            int counter = 0;

            // py:  Do something with the remainder
            // C#:  Do something with _x
            // sha: Do something with the padding

            MainLoop(message, hash);

            return ConversionHelpers.ToBigEndianByteArray(hash);
        }

        private static void MainLoop(byte[] beginState, uint[] hash) {
            byte[][] stateChunks = ByteArrayHelpers.SplitUp(beginState, ChunkSize);
            foreach (byte[] chunk in stateChunks) {

            }
        }
    }
}
