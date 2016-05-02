using System;
using System.Linq;

namespace CryptoPals
{
    public class Hash
    {
        public const string EmptySha1Hash = "da39a3ee5e6b4b0d3255bfef95601890afd80709";

        public static string Sha1(string message) {
            return Helpers.ToHexString(Sha1(Helpers.FromUTF8String(message)), false);
        }

        public static byte[] Sha1(byte[] message) {
            // Note: all numbers are in big endian notation - check if this doesn't conflict with things
            const int chunkSize = 64;

            // Initialization
            uint[] hash = { 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0 };

            int closestMultiple = Helpers.ClosestMultipleHigher(message.Length + sizeof(ulong), chunkSize);
            byte[] state = new byte[Math.Max(chunkSize, closestMultiple)];
            Array.Copy(message, state, message.Length);
            if (message.Length % chunkSize == 0) // Is this if nescessary?
                state[message.Length] = 0x80;
            byte[] lengthBytes = Helpers.ToBigEndian((uint)message.Length);
            Array.Copy(lengthBytes, 0, state, state.Length - lengthBytes.Length - 1, lengthBytes.Length);

            // Process the message in chunks
            byte[][] stateChunks = Helpers.SplitUp(state, chunkSize);
            foreach (byte[] chunk in stateChunks) {
                // Create the 80 words and the hash value for this chunk
                var words = new uint[80];
                for (int i = 0; i < 16; i++)
                    words[i] = Helpers.ToUInt(Helpers.CopyPartOf(chunk, i * 4, 4).Reverse().ToArray());
                for (int i = 16; i < 80; i++)
                    words[i] = Helpers.LeftRotate(words[i - 3] ^ words[i - 8] ^ words[i - 14] ^ words[i - 16], 1);

                uint[] chunkHash = (uint[])(hash.Clone());

                // Main for loop
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

                    uint temp = Helpers.LeftRotate(chunkHash[0], 5) + f + chunkHash[4] + k + words[i];
                    chunkHash[4] = chunkHash[3];
                    chunkHash[3] = chunkHash[2];
                    chunkHash[2] = Helpers.LeftRotate(chunkHash[1], 30);
                    chunkHash[1] = chunkHash[0];
                    chunkHash[0] = temp;
                }

                // Add this chunk's hash to the result so far
                for (int i = 0; i < hash.Length; i++)
                    hash[i] += chunkHash[i];
            }

            // Return the final hash
            return Helpers.ToBigEndianByteArray(hash);
        }
    }
}
