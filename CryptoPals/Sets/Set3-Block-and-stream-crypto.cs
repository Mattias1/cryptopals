using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Threading;

namespace CryptoPals
{
    class Set3 : Set
    {
        // Run all challenges of set 2
        public static bool runSet3() {
            return runSet(17, challenge17, challenge18, challenge19, challenge20, challenge21, () => challenge22(false), challenge23, challenge24);
        }

        // Create the MT19937 stream cipher and break it
        public static bool challenge24() {
            // Part 1. Create the MT19937 stream cipher
            byte[] input = ConversionHelpers.FromUTF8String("Test input");
            byte[] key = RandomHelpers.RandomByteArray(2);
            uint nonce = ConversionHelpers.ToUInt(RandomHelpers.RandomByteArray(2));

            byte[] cipher = encryptOrDecryptMt19937(input, key, nonce);
            byte[] backToInput = encryptOrDecryptMt19937(cipher, key, nonce);

            if (!MiscHelpers.Equals(backToInput, input)) {
                ConversionHelpers.PrintUTF8String(backToInput);
                return false;
            }

            // Part 2. Decrypt a known plaintext (prefixed with some random chars) and crack the key
            key = new byte[2];
            input = ConversionHelpers.FromUTF8String("AAAAAAAAAAAAAA");
            BlockCipherResult cipherAndNonce = encryptionOracle24(input);
            cipher = cipherAndNonce.Cipher;
            int nrOfPrefixBytes = cipher.Length - input.Length;
            byte[] prefixedInput = new byte[cipher.Length];
            Array.Copy(input, 0, prefixedInput, nrOfPrefixBytes, input.Length);
            byte[] nonceBytes = cipherAndNonce.Iv;
            byte[] keyStream = ByteArrayHelpers.XOR(prefixedInput, cipher);

            // There are 2 ways in which I can break this:
            // 1. Bruteforce the key (only 2^16 bits)
            // 2. Untwist the state to get the previous state (but this should not be not feasible)
            unchecked {
                for (int b1 = 0; b1 < 256; b1++)
                    for (int b2 = 0; b2 < 256; b2++) {
                        byte[] k = { (byte)b1, (byte)b2, nonceBytes[0], nonceBytes[1] };
                        var mt = new MersenneTwister(k);
                        byte[] tryStream = mt.NextBytes(cipher.Length);

                        bool failed = false;
                        for (int i = nrOfPrefixBytes; i < keyStream.Length; i++)
                            if (keyStream[i] != tryStream[i]) {
                                failed = true;
                                break;
                            }
                        if (failed)
                            continue;

                        key[0] = (byte)b1;
                        key[1] = (byte)b2;
                        Console.WriteLine("The seed: {0}", ConversionHelpers.ToHexString(k));
                    }
            }
            byte[] cipher2 = encryptOrDecryptMt19937(prefixedInput, key, ConversionHelpers.ToUInt(nonceBytes));
            Array.Copy(cipher, cipher2, nrOfPrefixBytes); // I don't know the random bytes, so I'l cheat a bit
            if (!MiscHelpers.Equals(cipher2, cipher)) {
                Console.WriteLine("Failed part 2");
                return false;
            }

            // Part 3. Generate and check for a random password token
            Console.WriteLine();
            uint startTimeStamp = MiscHelpers.UnixTimeU();
            string token = randomPasswordToken();
            Console.WriteLine(token);
            uint endTimeStamp = MiscHelpers.UnixTimeU();

            bool tokenIsMtFromCurrentTime = false;
            for (uint t = startTimeStamp; t <= endTimeStamp; t++)
                if (token == randomPasswordToken(t)) {
                    tokenIsMtFromCurrentTime = true;
                    Console.WriteLine("This token is generated with seed {0}, which is the current timestamp.", t);
                }

            return tokenIsMtFromCurrentTime;
        }

        static string randomPasswordToken(uint? seed = null, int nrOfBytes = 25) {
            var mt = new MersenneTwister(seed ?? MiscHelpers.UnixTimeU());
            byte[] result = mt.NextBytes(nrOfBytes);

            return ConversionHelpers.ToTokenString(result, nrOfBytes);
        }

        static BlockCipherResult encryptionOracle24(byte[] input) {
            if (fixedKey == null)
                fixedKey = new byte[2];
            byte[] randomPrefix = RandomHelpers.RandomByteArray(RandomHelpers.Random.Next(10, 20));
            fixedKey = RandomHelpers.RandomByteArray(2);
            uint nonce = ConversionHelpers.ToUInt(RandomHelpers.RandomByteArray(2));
            byte[] result = encryptOrDecryptMt19937(ByteArrayHelpers.Concatenate(randomPrefix, input), fixedKey, nonce);
            return BlockCipher.Result(result, ConversionHelpers.ToLittleEndian(nonce));
        }

        static byte[] encryptOrDecryptMt19937(byte[] input, byte[] key, uint nonce) {
            const int uintsize = 4;

            // Init the MT
            byte[] seed = new byte[uintsize];
            Array.Copy(key, seed, uintsize / 2);
            Array.Copy(ConversionHelpers.ToLittleEndian(nonce), 0, seed, uintsize / 2, uintsize / 2);
            var mt = new MersenneTwister(seed);

            // Generate the keystream
            byte[] keystream = mt.NextBytes(input.Length);

            return ByteArrayHelpers.XOR(input, keystream);
        }

        // Clone a MT19937 RNG from its output
        public static bool challenge23() {
            // The 'original' RNG
            MersenneTwister mt = new MersenneTwister(MiscHelpers.UnixTimeU()); // secret enough xD

            // Get the state
            var state = new uint[624];
            for (int i = 0; i < state.Length; i++)
                state[i] = MersenneTwister.Untemper(mt.Next());

            // Clone a new RNG
            MersenneTwister clonedMt = new MersenneTwister(state);

            // Output
            uint nextCloned = clonedMt.Next();
            uint nextOriginal = mt.Next();
            Console.WriteLine("Predicted next random number: {0}", ConversionHelpers.ToBitString(nextCloned));
            Console.WriteLine("Next random number:           {0}", ConversionHelpers.ToBitString(nextOriginal));

            // @Stop and think: the problem here is the invertability of the tampering.
            // If you use hashes, that's no longer possible, but the rng would become A LOT slower.
            return nextOriginal == nextCloned;
        }

        // Crack an MT19937 seeded on current timestamp
        static bool challenge22(bool hardMode = true) {
            // Send the request (and measure the begin and end times)
            Console.WriteLine("Sending the 'request'...");
            uint startTimestamp = MiscHelpers.UnixTimeU();
            uint randomNumber = getRandom22(hardMode);
            uint finishTimestamp = MiscHelpers.UnixTimeU();
            Console.WriteLine("Analyzing...\n");

            // Crack the seed
            var seeds = new List<uint>();
            for (uint s = startTimestamp; s <= finishTimestamp; s++) {
                uint trial = new MersenneTwister(s).Next();
                if (trial == randomNumber)
                    seeds.Add(s);
            }

            // Display the found seeds
            foreach (uint seed in seeds)
                Console.WriteLine("Seed: {0}", seed);

            return seeds.Count > 0;
        }

        static uint getRandom22(bool hardMode = true) {
            // Fake a web request - such a thing costs time...
            const int min = 40;
            const int max = 1000;
            int factor = hardMode ? 1000 : 1;

            Thread.Sleep(RandomHelpers.Random.Next(min * factor, max * factor));
            MersenneTwister mt = new MersenneTwister(MiscHelpers.UnixTimeU());
            Thread.Sleep(RandomHelpers.Random.Next(min * factor, max * factor));

            return mt.Next();
        }

        // Implement the mersenne twister (MT19937)
        public static bool challenge21() {
            // Values generated by a copy pasted python implementation from wikipedia
            uint[] expectedValues = new uint[]
            {
                3499211612, 581869302, 3890346734, 3586334585, 545404204, 4161255391, 3922919429, 949333985, 2715962298,
                1323567403, 418932835, 2350294565, 1196140740, 809094426, 2348838239, 4264392720, 4112460519, 4279768804
            };

            // Generate values myself now
            Console.WriteLine("Generated bits:\n");

            MersenneTwister mt = new MersenneTwister(5489);
            uint[] generatedValues = new uint[expectedValues.Length];
            for (int i = 0; i < generatedValues.Length; i++) {
                generatedValues[i] = mt.Next();
                Console.WriteLine(generatedValues[i]);
            }

            return MiscHelpers.Equals(generatedValues, expectedValues);
        }

        // Break fixed nonce CTR statistically (frequency analysis)
        public static bool challenge20() {
            // Get the input
            List<byte[]> input = encrypt20();
            int max = input.Max(c => c.Length);

            // The manual adjustments array
            var manualAdjustments = new byte[max];
            manualAdjustments[0] = 1;

            // Attack each byte of the keystream one by one, and use as many arrays in the input as possible for this keystream byte
            var keystream = new byte[max];
            for (int i = 0; i < max; i++) {
                var scoreList = new ScoreItem[manualAdjustments[i] + 1];

                byte[] merged = input.Where(c => c.Length > i).Select(c => c[i]).ToArray();
                Set1.attackSingleXOR(merged, scoreList);

                keystream[i] = scoreList.Last().KeyUsed.First();
            }

            // Print the result
            foreach (byte[] cipher in input)
                ConversionHelpers.PrintUTF8String(ByteArrayHelpers.XOR(cipher, keystream));

            byte[] lastLine = ByteArrayHelpers.XOR(input.Last(), keystream);
            return MiscHelpers.QuickCheck(lastLine, 55, "And we outta here / Yo, what happened to peace? / Peace");
        }

        static List<byte[]> encrypt20() {
            fixedKey = ConversionHelpers.FromHexString("0x41BDFD6EDEC769B61A7815447D9DB6F1"); // Randomly generated, but fixed
            ulong nonce = 0;

            List<byte[]> result = new List<byte[]>(40);
            using (FileStream stream = new FileStream("Data/20.txt", FileMode.Open)) {
                using (StreamReader reader = new StreamReader(stream)) {
                    string line;
                    while ((line = reader.ReadLine()) != null) {
                        byte[] raw = Convert.FromBase64String(line);
                        raw = encryptOrDecryptAesCtr(raw, fixedKey, nonce);
                        result.Add(raw);
                    }
                }
            }
            return result;
        }

        // Break fixed nonce CTR using frequency analysis (and some substitutions)
        public static bool challenge19() {
            // Helpers.PrintAsciiTable();

            List<byte[]> ciphers = encrypt19();
            byte[] keystreamSoFar = ConversionHelpers.FromHexString(
                "0x4838344276FE8B4E949618FE4EBF52F5A2AE678AA250F263A52DCD2688671E2D955373197343"
            );

            // Determine the size of the keystream we want to crack
            int keystreamSize = 38;
            keystreamSize = Math.Max(keystreamSize, keystreamSoFar.Length);
            var longCiphers = ciphers.Where(c => c.Length >= keystreamSize).ToList();

            // Merge them into one gigantic array and give them to the repeating XOR attacker from challenge 6
            var temp = new List<byte>();
            foreach (byte[] cipher in longCiphers)
                temp.AddRange(ByteArrayHelpers.CopyPartOf(cipher, 0, keystreamSize));
            byte[] merged = temp.ToArray();

            byte[] keystream = Set1.attackRepeatingXOR(merged, keystreamSize, keystreamSoFar);

            // Print the results for this key
            Console.WriteLine("Keystream size: {0} (max: {1}), #ciphers left: {2}",
                keystreamSize, ciphers.Max(c => c.Length), longCiphers.Count);
            ConversionHelpers.PrintHexString(keystream);
            Console.WriteLine();

            // foreach (var cipher in longCiphers.Take(10)) {
            //     byte[] part = Helpers.CopyPartOf(cipher, 0, keystreamSize);
            //     Helpers.PrintUTF8String(Helpers.XOR(part, keystream));
            // }

            // Now I'm done, let's print all the strings
            Console.WriteLine("\n\nAll decrypted strings:\n");
            foreach (var c in ciphers)
                ConversionHelpers.PrintUTF8String(ByteArrayHelpers.XOR(c, keystreamSoFar));

            return MiscHelpers.Equals(
                ConversionHelpers.FromHexString("0x4838344276FE8B4E949618FE4EBF52F5A2AE678AA250F263A52DCD2688671E2D955373197343"),
                keystream
            );
        }

        static List<byte[]> encrypt19() {
            fixedKey = ConversionHelpers.FromHexString("0x6CA0AF24369C8531BE2C7AE3AB8DBEA4"); // Randomly generated, but fixed
            ulong nonce = 0;

            List<byte[]> result = new List<byte[]>(40);
            using (FileStream stream = new FileStream("Data/19.txt", FileMode.Open)) {
                using (StreamReader reader = new StreamReader(stream)) {
                    string line;
                    while ((line = reader.ReadLine()) != null) {
                        byte[] raw = Convert.FromBase64String(line);
                        raw = encryptOrDecryptAesCtr(raw, fixedKey, nonce);
                        result.Add(raw);
                    }
                }
            }
            return result;
        }

        // Implement CTR mode of AES
        public static bool challenge18() {
            byte[] input = Convert.FromBase64String("L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==");
            byte[] key = ConversionHelpers.FromUTF8String("YELLOW SUBMARINE");
            ulong nonce = 0;

            byte[] result = encryptOrDecryptAesCtr(input, key, nonce);
            byte[] backToInput = encryptOrDecryptAesCtr(result, key, nonce);

            string test = ConversionHelpers.ToUTF8String(Set2.unPKCS7(result));
            ConversionHelpers.PrintUTF8String(Set2.unPKCS7(result));

            return MiscHelpers.QuickCheck(result, input.Length, "Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby")
                && MiscHelpers.Equals(input, backToInput);
        }

        public static byte[] encryptOrDecryptAesCtr(byte[] input, byte[] key, ulong nonce) {
            return encryptOrDecryptAesCtr(input, key, ConversionHelpers.ToLittleEndian(nonce));
        }
        public static byte[] encryptOrDecryptAesCtr(BlockCipherResult cipherAndNonce, byte[] key) {
            return encryptOrDecryptAesCtr(cipherAndNonce.Cipher, key, cipherAndNonce.Iv);
        }
        public static byte[] encryptOrDecryptAesCtr(byte[] input, byte[] key, byte[] nonce) {
            const int blocksize = 16;
            const int halfBlocksize = blocksize / 2;
            byte[] result = new byte[input.Length];
            byte[] nonceAndCounter = new byte[blocksize];
            ulong counter = 0;

            for (int i = 0; i < input.Length; i += blocksize) {
                byte[] block = ByteArrayHelpers.CopyPartOf(input, i, blocksize);

                Array.Copy(nonce, nonceAndCounter, halfBlocksize);
                Array.Copy(ConversionHelpers.ToLittleEndian(counter), 0, nonceAndCounter, halfBlocksize, halfBlocksize);

                byte[] keystream = BlockCipher.EncryptAES(nonceAndCounter, key, null, CipherMode.ECB, PaddingMode.None);

                block = ByteArrayHelpers.XOR(block, keystream);
                Array.Copy(block, 0, result, i, Math.Min(result.Length - i, blocksize));

                counter++;
            }

            return result;
        }

        // Decrypt a random CBC encrypted string, using a CBC padding oracle
        public static bool challenge17() {
            const int blocksize = 16;
            // The idea is to tamper the ciphertext in the following way:
            // - xor out the guessed byte (only if guessed right of course) and then xor in the new padding (say, 0x01).
            // - Check it's padding; if that padding is valid: then the last byte is, with high probability, 0x01,
            //   so our guess was right and we know a byte of the input.

            // Get the encrypted string we want to decrypt
            BlockCipherResult original = encryptionOracle17();
            byte[] answer = new byte[original.Cipher.Length];
            Console.Write("Cipher hex:   ");
            ConversionHelpers.PrintHexString(original.Cipher);

            for (int index = answer.Length - 1; index >= 0; index--) {
                // Setup for breaking the index-th byte
                int paddingbyte = blocksize - (index % blocksize);
                byte[] cipher = ByteArrayHelpers.CopyPartOf(original.Cipher, 0, MiscHelpers.ClosestMultipleHigher(index + 1, blocksize));
                byte[] iv = ByteArrayHelpers.Copy(original.Iv);

                // Set the bytes after the padding bytes
                if (index >= blocksize) {
                    for (int i = 1; i < paddingbyte; i++)
                        cipher[index + i - blocksize] = (byte)(original.Cipher[index + i - blocksize] ^ answer[index + i] ^ paddingbyte);
                }
                else {
                    for (int i = 1; i < paddingbyte; i++)
                        iv[index + i] = (byte)(original.Iv[index + i] ^ answer[index + i] ^ paddingbyte);
                }

                // Decrypt the index-th byte
                for (int b = 0; b < 256; b++) {
                    // To tamper the current block's plain, change the byte in the previous block's cipher (or iv)
                    if (index >= blocksize)
                        cipher[index - blocksize] = (byte)(original.Cipher[index - blocksize] ^ b ^ paddingbyte);
                    else
                        iv[index] = (byte)(original.Iv[index] ^ b ^ paddingbyte);
                    bool validPadding = paddingOracle17(cipher, iv);

                    // If the padding is valid, it's either the paddingbyte itself or the solution; save it.
                    if (validPadding) {
                        answer[index] = (byte)b;

                        if (b != paddingbyte)
                            break;
                    }
                }
            }

            Console.Write("Answer hex:   ");
            ConversionHelpers.PrintHexString(answer);
            Console.Write("Answer UTF-8: ");
            ConversionHelpers.PrintUTF8String(Set2.unPKCS7(answer));

            return MiscHelpers.Equals(Convert.FromBase64String("MDAw"), ByteArrayHelpers.CopyPartOf(answer, 0, 3));
        }

        static BlockCipherResult encryptionOracle17() {
            const int blocksize = 16;

            // Pick one of these strings (at random)
            string[] sources = new string[] {
                "MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
                "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
                "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
                "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
                "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
                "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
                "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
                "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
                "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
                "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93"
            };
            byte[] plain = Convert.FromBase64String(sources[RandomHelpers.Random.Next(10)]);

            // Generate a random (so unknown) key and use it throughout the rest of the program
            if (fixedKey == null)
                fixedKey = RandomHelpers.RandomByteArray(blocksize);

            // Generate a random iv and encrypt the chosen plaintext
            byte[] iv = RandomHelpers.RandomByteArray(blocksize);
            byte[] cipher = BlockCipher.EncryptAES(plain, fixedKey, iv, CipherMode.CBC, PaddingMode.PKCS7);

            return BlockCipher.Result(cipher, iv);
        }

        static bool paddingOracle17(byte[] cipher, byte[] iv) {
            // Return true or false depending on whether or not the padding is correct
            byte[] plain = BlockCipher.DecryptAES(cipher, fixedKey, iv, CipherMode.CBC, PaddingMode.None);
            return Set2.checkPKCS7(plain);
        }
    }
}
