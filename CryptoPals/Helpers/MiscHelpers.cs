using System;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;

namespace CryptoPals
{
    public static class MiscHelpers
    {
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

        public static uint LeftRotate(uint bits, int amount) {
            return (bits << amount) | (bits >> (32 - amount));
        }

        public static uint RightRotate(uint bits, int amount) {
            return (bits >> amount) | (bits << (32 - amount));
        }

        public static bool QuickCheck(byte[] result, int totalLength, string begin) {
            return result.Length == totalLength && ConversionHelpers.ToUTF8String(ByteArrayHelpers.CopyPartOf(result, 0, begin.Length)) == begin;
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

        public static int UnixTime(DateTime? t = null) {
            return (int)UnixTimeD(t);
        }
        public static uint UnixTimeU(DateTime? t = null) {
            return (uint)UnixTimeD(t);
        }
        public static double UnixTimeD(DateTime? t = null) {
            return (t ?? DateTime.Now).Subtract(new DateTime(1970, 1, 1)).TotalSeconds;
        }
    }
}
