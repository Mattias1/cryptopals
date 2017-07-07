using System;
using System.IO;
using System.Linq;
using System.Numerics;
using System.Text;

namespace CryptoPals
{
    public static class ConversionHelpers
    {
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

        public static string ToHexString(byte[] raw, bool add0x = false, int spaceEvery = 0) {
            // Initialize
            char[] result = new char[raw.Length * 2 + (spaceEvery == 0 ? 0 : raw.Length / spaceEvery)];
            const string hex = "0123456789abcdef";

            // Fill the char array
            for (int i = 0; i < raw.Length; i++) {
                int offset = spaceEvery == 0 ? 0 : (i / spaceEvery);
                result[offset + i * 2] = hex[raw[i] >> 4];
                result[offset + i * 2 + 1] = hex[raw[i] & 0x0f];
            }

            // Convert to string in one pass (and optionally add the "0x" in front)
            string final = new string(result);
            if (add0x)
                final = "0x" + final.ToUpper();
            return final;
        }
        public static string ToHexString(uint[] raw, bool add0x = false) {
            return ToHexString(ToBigEndianByteArray(raw), add0x);
        }

        private static string toHexString(byte raw) {
            const string hex = "0123456789abcdef";
            return $"{hex[raw >> 4]}{hex[raw & 0x0f]}";
        }

        public static string ToBitString(uint raw, bool add0b = true) {
            int size = raw < 0x100 ? 8 : 32;
            char[] result = new char[size];
            for (int i = 0; i < size; i++)
                result[i] = (raw & (1u << size - i - 1)) != 0 ? '1' : '0';

            return (add0b ? "0b" : "") + new string(result);
        }

        public static BigInteger ToBigInt(byte[] bytes) {
            if (bytes.Last() > 0x7f) {
                return new BigInteger(ByteArrayHelpers.Concatenate(bytes, new byte[1]));
            }
            return new BigInteger(bytes);
        }

        public static byte[] FromUTF8String(string message) {
            return Encoding.UTF8.GetBytes(message);
        }

        public static string ToUTF8String(byte[] raw) {
            return Encoding.UTF8.GetString(raw, 0, raw.Length);
        }

        public static byte FromUTF8Char(char c) {
            return FromUTF8String(new string(new char[] { c }))[0];
        }

        public static byte[] ReadBase64File(string filename) {
            string fileContent = File.ReadAllText(filename).Replace("\n", "").Replace("\r", "");
            return Convert.FromBase64String(fileContent);
        }


        public static void PrintUTF8String(byte[] raw) {
            Console.WriteLine(ToUTF8String(raw));
        }

        public static void PrintUTF8String(string prefix, byte[] raw) {
            Console.WriteLine(prefix + ToUTF8String(raw));
        }

        public static void PrintHexString(byte[] raw, bool add0x = true, int spaceEvery = 0) {
            Console.WriteLine(ToHexString(raw, add0x, spaceEvery));
        }
        public static void PrintHexString(uint[] raw, bool add0x = true) {
            Console.WriteLine(ToHexString(raw, add0x));
        }

        public static void PrintHexString(string prefix, byte[] raw, bool add0x = true, int spaceEvery = 0) {
            Console.WriteLine(prefix + ToHexString(raw, add0x, spaceEvery));
        }
        public static void PrintHexString(string prefix, uint[] raw, bool add0x = true) {
            Console.WriteLine(prefix + ToHexString(raw, add0x));
        }

        public static void PrintBigEndianHexString(string prefix, uint[] raw, bool add0x = true) {
            PrintHexString(prefix, ToBigEndianByteArray(raw), add0x);
        }


        public static string ToTokenString(byte[] raw, int maxLength = -1) {
            string result = Convert.ToBase64String(raw).Replace("=", "").Replace('/', '_');
            return maxLength < 0 ? result : result.Substring(0, maxLength);
        }

        public static byte[] FromUInt(uint i) {
            return BitConverter.GetBytes(i);
        }

        /// <summary>
        /// Little endian
        /// </summary>
        public static uint ToUInt(byte[] raw) {
            if (raw.Length == 4)
                return BitConverter.ToUInt32(raw, 0);
            byte[] four = new byte[4];
            Array.Copy(raw, four, Math.Min(raw.Length, four.Length));
            return ToUInt(four);
        }

        public static uint BigEndianToUint(byte[] raw) {
            return ToUInt(raw.Reverse().ToArray());
        }

        public static byte[] ToLittleEndianByteArray(uint[] raw) {
            return ByteArrayHelpers.Concatenate(raw.Select(i => ToLittleEndian(i)).ToArray());
        }
        public static byte[] ToBigEndianByteArray(uint[] raw) {
            return ByteArrayHelpers.Concatenate(raw.Select(i => ToBigEndian(i)).ToArray());
        }

        public static byte[] ToLittleEndian(uint number, int nrOfBytes = sizeof(uint)) {
            return ToLittleEndian((ulong)number, nrOfBytes);
        }
        public static byte[] ToLittleEndian(ulong number, int nrOfBytes = sizeof(ulong)) {
            byte[] result = new byte[nrOfBytes];

            const ulong fullByte = 0xFF;
            for (int i = 0; i < nrOfBytes; i++)
                result[i] = (byte)((number >> (i * 8)) & fullByte);

            return result;
        }

        public static byte[] ToBigEndian(uint number, int nrOfBytes = sizeof(uint)) {
            return ToBigEndian((ulong)number, nrOfBytes);
        }
        public static byte[] ToBigEndian(ulong number, int nrOfBytes = sizeof(ulong)) {
            byte[] result = new byte[nrOfBytes];

            const ulong fullByte = 0xFF;
            for (int i = 0; i < nrOfBytes; i++)
                result[nrOfBytes - i - 1] = (byte)((number >> (i * 8)) & fullByte);

            return result;
        }


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
    }
}