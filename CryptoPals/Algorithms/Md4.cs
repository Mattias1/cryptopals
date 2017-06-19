using System;
using System.Collections.Generic;

namespace CryptoPals
{
    public static class Md4
    {
        public const int ChunkSize = 64;
        public const int HashSize = 16;

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

        public static byte[] Mac(byte[] key, byte[] message) {
            return Hash(ByteArrayHelpers.Concatenate(key, message));
        }

        public static string Hash(string message) {
            return ConversionHelpers.ToHexString(Hash(ConversionHelpers.FromUTF8String(message)), false);
        }
        public static byte[] Hash(byte[] message) {
            uint[] hash = { 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476 };
            byte[] beginState = MdPadding(message);

            MainLoop(beginState, hash);

            return ConversionHelpers.ToLittleEndianByteArray(hash);
        }

        public static byte[] HashLengthExtension(byte[] extraMessage, int originalHashLengthGuess, uint[] initHash) {
            if (initHash.Length != 4)
                throw new ArgumentException("The hash initialization array should consist of 5 unsigned 32-bit integers.");

            uint[] hash = (uint[])initHash.Clone();
            byte[] beginState = MdPadding(extraMessage, originalHashLengthGuess + extraMessage.Length);

            MainLoop(beginState, hash);

            return ConversionHelpers.ToLittleEndianByteArray(hash);
        }


        public static byte[] MdPadding(byte[] message, int? overrideMessageLength = null) {
            // Almost the same as Sha1's MdPadding. This one uses little endian instead of big endian for the number, and has it moved 4 bytes to the left.
            int closestMultiple = MdPaddingLength(message);

            byte[] result = new byte[Math.Max(ChunkSize, closestMultiple)];
            Array.Copy(message, result, message.Length);

            result[message.Length] = 0x80;

            byte[] bitLength = ConversionHelpers.ToLittleEndian((uint)(overrideMessageLength ?? message.Length) * 8);
            Array.Copy(bitLength, 0, result, result.Length - bitLength.Length - 4, bitLength.Length);

            return result;
        }

        public static int MdPaddingLength(byte[] message) {
            return MiscHelpers.ClosestMultipleHigher(message.Length + sizeof(ulong), ChunkSize);
        }


        private static void MainLoop(byte[] beginState, uint[] hash) {
            byte[][] stateChunks = ByteArrayHelpers.SplitUp(beginState, ChunkSize);
            foreach (byte[] chunk in stateChunks) {
                uint[] words = GetWords(chunk);

                uint[] chunkHash = ProcessChunks((uint[])hash.Clone(), words);

                for (int i = 0; i < hash.Length; i++)
                    hash[i] += chunkHash[i];
            }
        }

        private static uint[] GetWords(byte[] chunk) {
            var words = new uint[16];
            int bytesProcessed = 0;

            foreach (byte b in chunk) {
                int c = bytesProcessed & 63;
                int i = c >> 2;
                int s = (c & 3) << 3;

                words[i] = (words[i] & ~((uint)255 << s)) | ((uint)b << s);

                bytesProcessed++;
            }

            return words;
        }

        private static uint[] ProcessChunks(uint[] chunkHash, uint[] words) {
            uint aa = chunkHash[0];
            uint bb = chunkHash[1];
            uint cc = chunkHash[2];
            uint dd = chunkHash[3];

            foreach (int k in new[] { 0, 4, 8, 12 }) {
                aa = Round1Operation(aa, bb, cc, dd, words[k], 3);
                dd = Round1Operation(dd, aa, bb, cc, words[k + 1], 7);
                cc = Round1Operation(cc, dd, aa, bb, words[k + 2], 11);
                bb = Round1Operation(bb, cc, dd, aa, words[k + 3], 19);
            }

            foreach (int k in new[] { 0, 1, 2, 3 }) {
                aa = Round2Operation(aa, bb, cc, dd, words[k], 3);
                dd = Round2Operation(dd, aa, bb, cc, words[k + 4], 5);
                cc = Round2Operation(cc, dd, aa, bb, words[k + 8], 9);
                bb = Round2Operation(bb, cc, dd, aa, words[k + 12], 13);
            }

            foreach (int k in new[] { 0, 2, 1, 3 }) {
                aa = Round3Operation(aa, bb, cc, dd, words[k], 3);
                dd = Round3Operation(dd, aa, bb, cc, words[k + 8], 9);
                cc = Round3Operation(cc, dd, aa, bb, words[k + 4], 11);
                bb = Round3Operation(bb, cc, dd, aa, words[k + 12], 15);
            }

            return new uint[] { aa, bb, cc, dd };
        }

        private static uint Round1Operation(uint a, uint b, uint c, uint d, uint xk, int s) {
            return MiscHelpers.LeftRotate(a + ((b & c) | (~b & d)) + xk, s);
        }

        private static uint Round2Operation(uint a, uint b, uint c, uint d, uint xk, int s) {
            return MiscHelpers.LeftRotate(a + ((b & c) | (b & d) | (c & d)) + xk + 0x5a827999, s);
        }

        private static uint Round3Operation(uint a, uint b, uint c, uint d, uint xk, int s) {
            return MiscHelpers.LeftRotate(a + (b ^ c ^ d) + xk + 0x6ed9eba1, s);
        }
    }
}
