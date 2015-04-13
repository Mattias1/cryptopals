using System;
using System.Text;

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
        /// Converts a byte array to a normal UTF-8 string
        /// </summary>
        /// <param name="raw"></param>
        /// <returns></returns>
        public static string ToUTF8String(byte[] raw) {
            return Encoding.UTF8.GetString(raw, 0, raw.Length);
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
        /// Calculate a score as to how close it is to the 'perfect english text'.
        /// The lower the score, the closer.
        /// </summary>
        /// <param name="s"></param>
        /// <returns></returns>
        public static double FrequencyScore(string s) {
            // The frequencies of english text (%)
            double[] frequencies_en = {
                8.167, 1.492, 2.782, 4.253, 12.702, 2.228, 2.015,                   // a - g
                6.094, 6.966, .153, .772, 4.025, 2.406, 6.749, 7.507, 1.929,        // h - p
                .095, 5.987, 6.327, 9.056, 2.758, .978, 2.360, .150, 1.974, .074,   // q - z
                20, 0                                                               // Space, Other characters (assume they don't occur)
            };

            // Count the occurances of every letter
            s = s.ToLower();
            double[] counts = new double[frequencies_en.Length];
            for (int i = 0; i < s.Length; i++) {
                if ('a' <= s[i] && s[i] <= 'z')
                    counts[s[i] - 'a']++;
                else if (s[i] == ' ')
                    counts[26]++;
                else
                    counts[counts.Length - 1]++;
            }

            // Calculate a single score, by giving more penalty the further away our counted score is to the optimal frequency.
            double normalizeFactor = 100 / s.Length;
            double score = 0;
            for (int i = 0; i < counts.Length; i++)
                score += Math.Abs(frequencies_en[i] - counts[i] * normalizeFactor);
            return score;
        }
    }
}
