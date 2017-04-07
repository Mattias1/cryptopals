using System;

namespace CryptoPals
{
    public class Set
    {
        protected static byte[] fixedKey, fixedBytes;

        protected static bool runSet(params Func<bool>[] challenges) {
            bool result = true;

            for (int i = 0; i < challenges.Length; i++) {
                Console.WriteLine($"{(i > 0 ? "\n\n" : "")}Challenge {i + 1}:");
                result &= challenges[i]();
                reset();
            }

            return result;
        }

        private static void reset() {
            fixedKey = null;
            fixedBytes = null;
        }
    }
}
