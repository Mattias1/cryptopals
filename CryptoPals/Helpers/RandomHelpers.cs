﻿using System;

namespace CryptoPals
{
    public static class RandomHelpers
    {
        private static Random random;
        public static Random Random => random ?? (random = new Random());

        public static byte[] RandomByteArray(int length) {
            byte[] result = new byte[length];
            Random.NextBytes(result);
            return result;
        }

        public static string RandomString(int length = -1) {
            if (length < 0)
                length = Random.Next(3, 10);
            return ConversionHelpers.ToTokenString(RandomByteArray(length), length);
        }
    }
}
