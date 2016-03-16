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
    }
}
