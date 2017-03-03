using System;
using System.Linq;

namespace CryptoPals
{
    public static class ByteArrayHelpers
    {
        public static byte[] Copy(byte[] raw) {
            byte[] result = new byte[raw.Length];
            Array.Copy(raw, result, raw.Length);
            return result;
        }

        public static byte[] CopyPartOf(byte[] raw, int start, int length) {
            byte[] result = new byte[length];
            if (start + length > raw.Length)
                Array.Copy(raw, start, result, 0, raw.Length - start);
            else
                Array.Copy(raw, start, result, 0, length);
            return result;
        }

        public static byte[] Concatenate(params byte[][] arrays) {
            int length = arrays.Sum(raw => raw.Length);
            byte[] result = new byte[length];

            int index = 0;
            foreach (byte[] raw in arrays) {
                Array.Copy(raw, 0, result, index, raw.Length);
                index += raw.Length;
            }
            return result;
        }

        public static byte[][] SplitUp(byte[] raw, int blocksize) {
            byte[][] result = new byte[(raw.Length + blocksize - 1) / blocksize][]; // Integer division rounded up (beware of overflowing)
            for (int i = 0; i < result.Length; i++)
                result[i] = CopyPartOf(raw, i * blocksize, blocksize);
            return result;
        }

        public static byte[][] Transpose(byte[][] blocks) {
            if (blocks.Length == 0)
                return new byte[0][];

            byte[][] result = new byte[blocks[0].Length][]; // This is the blocksize
            int smallIndex = blocks[blocks.Length - 1].Length;
            for (int i = 0; i < result.Length; i++) {
                result[i] = new byte[i >= smallIndex ? blocks.Length - 1 : blocks.Length]; // This is the number of i-th bytes of all blocks
                for (int b = 0; b < blocks.Length; b++)
                    result[i][b] = blocks[b][i];
            }
            return result;
        }

        /// <summary>
        /// Pad an array so that it is a multiple of a certain blocksize (or don't pad if it already is)
        /// </summary>
        /// <param name="raw"></param>
        /// <param name="blocksize"></param>
        /// <param name="padByte"></param>
        /// <returns></returns>
        public static byte[] PadOptionalWith(byte[] raw, int blocksize, byte padByte = 0) {
            byte[] result = new byte[((raw.Length + blocksize - 1) / blocksize) * blocksize]; // Integer division rounded up (beware of overflowing) and then multiply back

            Array.Copy(raw, result, raw.Length);
            for (int i = raw.Length; i < result.Length; i++)
                result[i] = padByte;

            return result;
        }

        /// <summary>
        /// Pad an array so that it is a multiple of a certain blocksize (if it already is, add an entire block)
        /// </summary>
        /// <param name="raw"></param>
        /// <param name="blocksize"></param>
        /// <param name="padByte"></param>
        /// <returns></returns>
        public static byte[] ForcePadWith(byte[] raw, int blocksize, byte padByte = 0) {
            byte[] result = new byte[(raw.Length / blocksize + 1) * blocksize];

            Array.Copy(raw, result, raw.Length);
            for (int i = raw.Length; i < result.Length; i++)
                result[i] = padByte;

            return result;
        }

        /// <summary>
        /// X-OR a message with a key (repeated if shorter than message)
        /// </summary>
        /// <param name="message">The message to XOR</param>
        /// <param name="key">The key to xor with</param>
        /// <returns></returns>
        public static byte[] XOR(byte[] message, byte[] key) {
            byte[] result = new byte[message.Length];
            for (int i = 0; i < message.Length; i++)
                result[i] = (byte)(message[i] ^ key[i % key.Length]);
            return result;
        }

        public static byte[] XorAt(byte[] raw, int index, int xorWith) {
            raw[index] = (byte)(raw[index] ^ xorWith);
            return raw;
        }
    }
}