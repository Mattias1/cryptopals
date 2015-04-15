using System;
using System.Text;

namespace CryptoPals
{
    static class Helpers
    {
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
            string hex = "0123456789abcdef";

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

        // Misc
        /// <summary>
        /// Copy a part of the raw array
        /// </summary>
        /// <param name="raw"></param>
        /// <param name="start">The start index of the part of the raw array that we want to copy</param>
        /// <param name="length">The length of the part we want to copy</param>
        /// <returns></returns>
        public static byte[] CopyPartOf(byte[] raw, int start, int length) {
            byte[] result = new byte[length];
            Array.Copy(raw, start, result, 0, length);
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
    }
}
