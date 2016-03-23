using System;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Windows.Forms;

namespace CryptoPals
{
    static class Helpers
    {
        // Random
        private static Random random;
        public static Random Random => random ?? (random = new Random());

        public static byte[] RandomByteArray(int length) {
            byte[] result = new byte[length];
            Helpers.Random.NextBytes(result);
            return result;
        }

        // Encodings
        /// <summary>
        /// Convert a string with hexadecimal digits [0..9, A..F]* to a byte array.
        /// </summary>
        /// <param name="hexString"></param>
        /// <returns></returns>
        public static byte[] FromHexString(string hexString) {
            // Initialize: work with a lowercase string without "0x" in front and without spaces
            hexString = hexString.ToLower().Replace(" ", "");
            if (hexString.Length > 1 && hexString[0] == '0' && hexString[1] == 'x')
                hexString = hexString.Substring(2);
            byte[] result = new byte[hexString.Length / 2 + hexString.Length % 2];

            // Fill the byte array
            for (int i = 0; i < hexString.Length; i++) {
                int idx = i / 2;
                char c = hexString[i];
                result[idx] <<= 4;
                if ('0' <= c && c <= '9')
                    result[idx] |= (byte)(c - '0');
                else if ('a' <= c && c <= 'f')
                    result[idx] |= (byte)(10 + c - 'a');
                else
                    throw new Exception("Not a hex string.");
            }
            // Make sure to shift the last byte in case of an odd string length
            if (result.Length > 0)
                result[result.Length - 1] <<= hexString.Length % 2 * 4;
            return result;
        }
        /// <summary>
        /// Converts a byte array to a string with hexadecimal digits.
        /// </summary>
        /// <param name="raw"></param>
        /// <returns></returns>
        public static string ToHexString(byte[] raw, bool add0x = false) {
            // Initialize
            char[] result = new char[raw.Length * 2];
            const string hex = "0123456789abcdef";

            // Fill the char array
            for (int i = 0; i < raw.Length; i++) {
                result[i * 2] = hex[raw[i] >> 4];
                result[i * 2 + 1] = hex[raw[i] & 0x0f];
            }

            // Convert to string in one pass (and optionally add the "0x" in front)
            string final = new string(result);
            if (add0x)
                final = "0x" + final.ToUpper();
            return final;
        }

        private static string toHexString(byte raw) {
            const string hex = "0123456789abcdef";
            return $"{hex[raw >> 4]}{hex[raw & 0x0f]}";
        }

        /// <summary>
        /// Convert a raw set of bits (uing) to bitstring (string)
        /// </summary>
        /// <param name="raw"></param>
        /// <param name="add0b"></param>
        /// <returns></returns>
        public static string ToBitString(uint raw, bool add0b = true) {
            int size = raw < 0x100 ? 8 : 32;
            char[] result = new char[size];
            for (int i = 0; i <size; i++)
                result[i] = (raw & (1u << size - i - 1)) != 0 ? '1' : '0';

            return (add0b ? "0b" : "") + new string(result);
        }

        /// <summary>
        /// Convert a normal UTF-8 string into a byte array
        /// </summary>
        /// <param name="message"></param>
        /// <returns></returns>
        public static byte[] FromUTF8String(string message) {
            return Encoding.UTF8.GetBytes(message);
        }
        /// <summary>
        /// Converts a byte array to a normal UTF-8 string
        /// </summary>
        /// <param name="raw"></param>
        /// <returns></returns>
        public static string ToUTF8String(byte[] raw) {
            return Encoding.UTF8.GetString(raw, 0, raw.Length);
        }

        /// <summary>
        /// Print a byte array as a normal UTF-8 string to the console
        /// </summary>
        /// <param name="raw"></param>
        public static void PrintUTF8String(byte[] raw) {
            Console.WriteLine(ToUTF8String(raw));
        }
        /// <summary>
        /// Print a byte array as a hexadecimal string to the console
        /// </summary>
        /// <param name="raw"></param>
        public static void PrintHexString(byte[] raw, bool add0x = true) {
            Console.WriteLine(ToHexString(raw, add0x));
        }

        /// <summary>
        /// Return the content of a base64 encoded file as a byte array
        /// </summary>
        /// <param name="filename"></param>
        /// <returns></returns>
        public static byte[] ReadBase64File(string filename) {
            string fileContent = File.ReadAllText(filename).Replace("\n", "").Replace("\r", "");
            return Convert.FromBase64String(fileContent);
        }

        /// <summary>
        /// Get the bytes of a number in little endian format
        /// </summary>
        /// <param name="number"></param>
        /// <returns></returns>
        public static byte[] LittleEndian(ulong number) {
            int nrOfBytes = sizeof(ulong);
            byte[] result = new byte[nrOfBytes];

            const ulong fullByte = 0xFF;
            for (int i = 0; i < nrOfBytes; i++)
                result[i] = (byte)(number & fullByte >> (i * 8));

            return result;
        }

        /// <summary>
        /// Print (parts of) the ASCII table to the console
        /// </summary>
        public static string PrintAsciiTable(bool hex = true) {
            string[] toPrint = {
                "abcdefghijklm",
                "nopqrstuvwxyz",
                "ABCDEFGHIJKLM",
                "NOPQRSTUVWXYZ",
                "0123456789",
                " !\"',.:?"
            };
            int pad = hex ? 2 : 3;
            int length = toPrint.First().Length * (pad + 1) + 1;
            StringBuilder sb = new StringBuilder();

            sb.AppendLine("ASCII table:");
            foreach (var chars in toPrint.Select(s => s.ToCharArray())) {
                sb.AppendLine("".PadRight(length, '-'));
                foreach (char c in chars)
                    sb.Append(' ').Append(c.ToString().PadRight(pad, ' '));
                sb.AppendLine();
                foreach (byte c in chars.Select(c => (byte)c)) {
                    string s = hex ? toHexString(c) : c.ToString();
                    sb.Append(' ').Append(s.PadRight(pad, ' '));
                }
                sb.AppendLine();
            }
            sb.AppendLine("".PadRight(length, '-'));

            string result = sb.ToString();
            Console.WriteLine(result);
            return result;
        }

        // Byte array manipulations
        /// <summary>
        /// Copy a full byte array
        /// </summary>
        /// <param name="raw"></param>
        /// <returns></returns>
        public static byte[] Copy(byte[] raw) {
            byte[] result = new byte[raw.Length];
            Array.Copy(raw, result, raw.Length);
            return result;
        }

        /// <summary>
        /// Copy a part of the raw array
        /// </summary>
        /// <param name="raw"></param>
        /// <param name="start">The start index of the part of the raw array that we want to copy</param>
        /// <param name="length">The length of the part we want to copy</param>
        /// <returns></returns>
        public static byte[] CopyPartOf(byte[] raw, int start, int length) {
            byte[] result = new byte[length];
            if (start + length > raw.Length)
                Array.Copy(raw, start, result, 0, raw.Length - start);
            else
                Array.Copy(raw, start, result, 0, length);
            return result;
        }

        /// <summary>
        /// Concatenate all given raw arrays into one byte array
        /// </summary>
        /// <param name="arrays"></param>
        /// <returns></returns>
        public static byte[] Concatenate(params byte[][] arrays) {
            // Create an array with the correct length
            int length = arrays.Sum(raw => raw.Length);
            byte[] result = new byte[length];
            // Fill it
            int index = 0;
            foreach (byte[] raw in arrays) {
                Array.Copy(raw, 0, result, index, raw.Length);
                index += raw.Length;
            }
            return result;
        }

        /// <summary>
        /// Split up the raw byte array in smaller byte arrays of a fixed (maximum) blocksize
        /// </summary>
        /// <param name="raw"></param>
        /// <param name="blocksize"></param>
        /// <returns></returns>
        public static byte[][] SplitUp(byte[] raw, int blocksize) {
            byte[][] result = new byte[(raw.Length + blocksize - 1) / blocksize][]; // Integer division rounded up (beware of overflowing)
            for (int i = 0; i < result.Length; i++)
                result[i] = CopyPartOf(raw, i * blocksize, blocksize);
            return result;
        }

        /// <summary>
        /// Transpose the array of byte arrays
        /// </summary>
        /// <param name="blocks"></param>
        /// <returns></returns>
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

        /// <summary>
        /// XOR an array in place at a specific position with a specific byte
        /// </summary>
        /// <param name="raw"></param>
        /// <param name="index"></param>
        /// <param name="xorWith"></param>
        public static byte[] XorAt(byte[] raw, int index, int xorWith) {
            raw[index] = (byte)(raw[index] ^ xorWith);
            return raw;
        }

        // Misc
        /// <summary>
        /// Return whether or not two byte arrays are equal (in content, not (nescessarily) memory address)
        /// </summary>
        /// <param name="a"></param>
        /// <param name="b"></param>
        /// <returns></returns>
        public static bool Equals<T>(T[] a, T[] b)
                where T : IEquatable<T> {
            if (a.Length != b.Length)
                return false;

            for (int i = 0; i < a.Length; i++)
                if (!a[i].Equals(b[i]))
                    return false;
            return true;
        }

        /// <summary>
        /// Calculate the Hamming distance between two byte arrays
        /// The hamming distance is the number of different bits
        /// </summary>
        /// <param name="a"></param>
        /// <param name="b"></param>
        /// <returns></returns>
        public static int HammingDistance(byte[] a, byte[] b) {
            // Hamming distance: the number of differing bits
            if (a.Length != b.Length)
                throw new Exception("Hamming distance is only valid for arrays of equal length");

            int result = 0;
            for (int i = 0; i < a.Length; i++)
                for (int bit = 1; bit < 256; bit <<= 1)
                    if ((a[i] & bit) != (b[i] & bit))
                        result++;
            return result;
        }

        /// <summary>
        /// Do a quick check on whether or not the result is correct-ish
        /// </summary>
        /// <param name="result"></param>
        /// <param name="totalLength"></param>
        /// <param name="begin"></param>
        /// <returns></returns>
        public static bool QuickCheck(byte[] result, int totalLength, string begin) {
            return result.Length == totalLength && Helpers.ToUTF8String(Helpers.CopyPartOf(result, 0, begin.Length)) == begin;
        }

        /// <summary>
        /// Get the closest multiple of the divisor greater or equal to the count
        /// </summary>
        /// <param name="count"></param>
        /// <param name="divisor"></param>
        /// <returns></returns>
        public static int ClosestMultipleHigher(int count, int divisor) {
            int difference = count % divisor;
            if (difference == 0)
                return count;
            return count + divisor - difference;
        }
        /// <summary>
        /// Get the closest multiple of the divisor smaller or equal to the count
        /// </summary>
        /// <param name="count"></param>
        /// <param name="divisor"></param>
        /// <returns></returns>
        public static int ClosestMultipleLower(int count, int divisor) {
            return count - count % divisor;
        }

        /// <summary>
        /// Save a string to clipboard
        /// </summary>
        /// <param name="s"></param>
        public static bool ToClipboard(string s) {
            try {
                Clipboard.SetText(s);
                return true;
            }
            catch (ThreadStateException) {
                return false;
            }
        }
        /// <summary>
        /// Save a bytearray to clipoard in hex format
        /// </summary>
        /// <param name="raw"></param>
        /// <param name="add0x"></param>
        public static bool ToClipboard(byte[] raw, bool add0x = true) {
            return ToClipboard(ToHexString(raw, add0x));
        }

        /// <summary>
        /// The amount of seconds sinds 1 Jan 1970 for time t
        /// </summary>
        /// <param name="t"></param>
        /// <returns></returns>
        public static int UnixTime(DateTime? t = null) {
            return (int)UnixTimeD(t);
        }
        /// <summary>
        /// The amount of seconds sinds 1 Jan 1970 for time t
        /// </summary>
        /// <param name="t"></param>
        /// <returns></returns>
        public static uint UnixTimeU(DateTime? t = null) {
            return (uint)UnixTimeD(t);
        }
        /// <summary>
        /// The amount of seconds sinds 1 Jan 1970 for time t
        /// </summary>
        /// <param name="t"></param>
        /// <returns></returns>
        public static double UnixTimeD(DateTime? t = null) {
            return (t ?? DateTime.Now).Subtract(new DateTime(1970, 1, 1)).TotalSeconds;
        }
    }
}
