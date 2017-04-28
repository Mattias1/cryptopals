using System;
using System.Collections.Generic;
using System.Linq;

namespace CryptoPals
{
    public static class Sha1
    {
        public const int ChunkSize = 64;

        public static Dictionary<string, string> KnownHashes {
            get {
                return new Dictionary<string, string>
                {
                    {"", "da39a3ee5e6b4b0d3255bfef95601890afd80709"},
                    {"The quick brown fox jumps over the lazy dog", "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12"},
                    {"The quick brown fox jumps over the lazy cog", "de9f2c7fd25e1b3afad3e85a0bd17d9b100db4b3"}
                };
            }
        }

        public static Dictionary<string, string> KnownHmacHashes {
            get {
                // { "key;message" , "expected SHA1-HMAC" }
                return new Dictionary<string, string> {
                    {";", "fbdb1d1b18aa6c08324b7d64b71fb76370690e1d"},
                    {"key;The quick brown fox jumps over the lazy dog", "de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9"}
                };
            }
        }

        public static byte[] Mac(byte[] key, byte[] message) {
            return Hash(ByteArrayHelpers.Concatenate(key, message));
        }

        public static string Hmac(string key, string message) {
            byte[] hash = Hmac(ConversionHelpers.FromUTF8String(key), ConversionHelpers.FromUTF8String(message));
            return ConversionHelpers.ToHexString(hash, false);
        }
        public static byte[] Hmac(byte[] key, byte[] message) {
            byte[] opad = ByteArrayHelpers.Create(ChunkSize, 0x5c);
            byte[] ipad = ByteArrayHelpers.Create(ChunkSize, 0x36);
            byte[] derivedKey = DeriveHmacKey(key);

            return Hash(ByteArrayHelpers.Concatenate(
                ByteArrayHelpers.XOR(derivedKey, opad),
                Hash(ByteArrayHelpers.Concatenate(
                    ByteArrayHelpers.XOR(derivedKey, ipad),
                    message
                ))
            ));
        }

        private static byte[] DeriveHmacKey(byte[] key) {
            if (key.Length == ChunkSize) {
                return key;
            }
            if (key.Length < ChunkSize) {
                return ByteArrayHelpers.ForcePadWith(key, ChunkSize, 0);
            }
            return Hash(key);
        }

        public static string Hash(string message) {
            return ConversionHelpers.ToHexString(Hash(ConversionHelpers.FromUTF8String(message)), false);
        }
        public static byte[] Hash(byte[] message) {
            uint[] hash = { 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0 };
            byte[] beginState = MdPadding(message);

            MainLoop(beginState, hash);

            return ConversionHelpers.ToBigEndianByteArray(hash);
        }

        public static byte[] HashLengthExtension(byte[] extraMessage, int originalHashLengthGuess, uint[] initHash) {
            if (initHash.Length != 5)
                throw new ArgumentException("The hash initialization array should consist of 5 unsigned 32-bit integers.");

            uint[] hash = (uint[])initHash.Clone();
            byte[] beginState = MdPadding(extraMessage, originalHashLengthGuess + extraMessage.Length);

            MainLoop(beginState, hash);

            return ConversionHelpers.ToBigEndianByteArray(hash);
        }


        public static byte[] MdPadding(byte[] message, int? overrideMessageLength = null) {
            int closestMultiple = MdPaddingLength(message);

            byte[] result = new byte[Math.Max(ChunkSize, closestMultiple)];
            Array.Copy(message, result, message.Length);

            result[message.Length] = 0x80;

            byte[] bitLength = ConversionHelpers.ToBigEndian((uint)(overrideMessageLength ?? message.Length) * 8);
            Array.Copy(bitLength, 0, result, result.Length - bitLength.Length, bitLength.Length);

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
            var words = new uint[80];
            for (int i = 0; i < 16; i++)
                words[i] = ConversionHelpers.ToUInt(ByteArrayHelpers.CopyPartOf(chunk, i * 4, 4).Reverse().ToArray());
            for (int i = 16; i < 80; i++)
                words[i] = MiscHelpers.LeftRotate(words[i - 3] ^ words[i - 8] ^ words[i - 14] ^ words[i - 16], 1);
            return words;
        }

        private static uint[] ProcessChunks(uint[] chunkHash, uint[] words) {
            for (int i = 0; i < words.Length; i++) {
                uint f, k;
                if (i < 20) {
                    f = (chunkHash[1] & chunkHash[2]) | (~chunkHash[1] & chunkHash[3]);
                    k = 0x5A827999;
                }
                else if (i < 40) {
                    f = chunkHash[1] ^ chunkHash[2] ^ chunkHash[3];
                    k = 0x6ED9EBA1;
                }
                else if (i < 60) {
                    f = (chunkHash[1] & chunkHash[2]) | (chunkHash[1] & chunkHash[3]) | (chunkHash[2] & chunkHash[3]);
                    k = 0x8F1BBCDC;
                }
                else {
                    f = chunkHash[1] ^ chunkHash[2] ^ chunkHash[3];
                    k = 0xCA62C1D6;
                }

                uint temp = MiscHelpers.LeftRotate(chunkHash[0], 5) + f + chunkHash[4] + k + words[i];
                chunkHash[4] = chunkHash[3];
                chunkHash[3] = chunkHash[2];
                chunkHash[2] = MiscHelpers.LeftRotate(chunkHash[1], 30);
                chunkHash[1] = chunkHash[0];
                chunkHash[0] = temp;
            }

            return chunkHash;
        }
    }
}
