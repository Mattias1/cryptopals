using System;

namespace CryptoPals
{
    class MersenneTwister
    {
        // The constants
        const int w = 32;
        const int n = 624;
        const int m = 397;
        const int r = 31;
        const uint a = 0x9908B0DF;
        const int u = 11;
        const uint d = 0xFFFFFFFF;
        const int s = 7;
        const uint b = 0x9D2C5680;
        const int t = 15;
        const uint c = 0xEFC60000;
        const int l = 18;

        const uint f = 1812433253; // Only used in initialization

        const uint lowerMask = (1u << r) - 1;
        const uint upperMask = ~lowerMask;

        uint[] state;
        int index;

        /// <summary>
        /// Seed the Mersenne twister (MT19937)
        /// </summary>
        /// <param name="seed"></param>
        public MersenneTwister(uint seed = 5489) {
            // Initialize the state
            this.index = n;
            this.state = new uint[n]; // The state
            this.state[0] = seed;
            for (uint i = 1; i < n; i++)
                this.state[i] = f * (this.state[i - 1] ^ (this.state[i - 1] >> (w - 2))) + i;
        }
        /// <summary>
        /// Clone from a mersenne twister state
        /// </summary>
        /// <param name="state"></param>
        public MersenneTwister(uint[] state)
        {
            this.index = n;
            this.state = state;
        }

        /// <summary>
        /// Extract the next 32 bits
        /// </summary>
        /// <returns></returns>
        public uint Next() {
            // Extract the next number
            if (this.index >= n)
                this.twist();

            uint y = this.state[this.index];
            y = y ^ ((y >> u) & d);
            y = y ^ ((y << s) & b);
            y = y ^ ((y << t) & c);
            y = y ^ (y >> l);

            this.index++;
            return y;
        }

        private void twist() {
            // Generate the next n values for the state
            for (int i = 0; i < n; i++) {
                uint x = (this.state[i] & upperMask) + (this.state[(i + 1) % n] & lowerMask);
                uint xA = x >> 1;
                if (x % 2 != 0)
                    xA = xA ^ a;
                this.state[i] = this.state[(i + m) % n] ^ xA;
            }
            this.index = 0;
        }

        /// <summary>
        /// Untemper an extracted value
        /// </summary>
        /// <param name="y"></param>
        /// <returns></returns>
        public static uint Untemper(uint y) {
            y = untemperRightShift(y, l);
            y = untemperLeftShift(y, c, t);
            y = untemperLeftShift(y, b, s);
            y = untemperRightShift(y, u);

            return y;
        }
        
        static uint untemperRightShift(uint y, int bitsShifted) {
            if (bitsShifted <= 0)
                throw new Exception("The untemperRightShift method expects the # bits shifted to be at least 1");
            const int size = 32;
            uint result = 0;

            // The idea: we know that the bits are shifted x to the right, so the x left most bits we receive are correct
            uint mask = 1u << (size - 1);
            for (int i = 0; i < bitsShifted; i++) {
                result |= y & mask;
                mask >>= 1;
            }

            // Then, since we know what the next bit from the left is xored with, we know what it must be
            while (mask != 0) {
                result |= ((result >> bitsShifted) ^ y) & mask;
                mask >>= 1;
            }

            return result;
        }
        static uint untemperLeftShift(uint y, uint magicNumber, int bitsShifted) {
            if (bitsShifted <= 0)
                throw new Exception("The untemperLeftShift method expects the # bits shifted to be at least 1");
            uint result = 0;

            // The idea: we know that the bits are shifted x to the left, so the x right most bits we receive are correct
            uint mask = 1;
            for (int i = 0; i < bitsShifted; i++) {
                result |= y & mask;
                mask <<= 1;
            }

            // Then, since we know what the next bit from the right is xored with, we know what it must be
            while (mask != 0) {
                result |= (((result << bitsShifted) & magicNumber) ^ y) & mask;
                mask <<= 1;
            }

            return result;
        }
    }
}
