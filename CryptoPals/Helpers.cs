using System;

namespace CryptoPals
{
    static class Helpers
    {
        /// <summary>
        /// Convert a string with hexadecimal digits [0..9, A..F]* to a byte array.
        /// </summary>
        /// <param name="hexString"></param>
        /// <returns></returns>
        public static byte[] FromHexString(string hexString) {
            // Initialize: work with a lowercase string without "0x" in front and without spaces
            hexString = hexString.ToLower().Replace(" ", "");
            if (hexString[0] == '0' && hexString[1] == 'x')
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
            result[result.Length - 1] <<= hexString.Length % 2 * 4;
            return result;
        }

        /// <summary>
        /// Converts a byte array to a string with hexadecimal digits.
        /// </summary>
        /// <param name="bytes"></param>
        /// <returns></returns>
        public static string ToHexString(byte[] bytes, bool add0x = false) {
            // Initialize
            char[] result = new char[bytes.Length * 2];
            string hex = "0123456789abcdef";

            // Fill the char array
            for (int i = 0; i < bytes.Length; i++) {
                result[i * 2] = hex[bytes[i] >> 4];
                result[i * 2 + 1] = hex[bytes[i] & 0x0f];
            }

            // Convert to string in one pass (and optionally add the "0x" in front)
            string final = new string(result);
            if (add0x)
                final = "0x" + final.ToUpper();
            return final;
        }
    }
}
