using System;

namespace CryptoPals
{
    public class Set
    {
        protected static byte[] fixedKey, fixedBytes;

        protected static bool runSet(int offset, params Func<bool>[] challenges) {
            for (int i = 0; i < challenges.Length; i++) {
                Console.WriteLine($"{(i > 0 ? "\n\n" : "")}Challenge {i + offset}:");
                if (!challenges[i]())
                    return false;
                reset();
            }

            return true;
        }

        private static void reset() {
            fixedKey = null;
            fixedBytes = null;
        }
    }
}
