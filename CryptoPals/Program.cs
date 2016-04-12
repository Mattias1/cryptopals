using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Threading;

namespace CryptoPals
{
    class Program
    {
        static byte[] fixedKey, fixedBytes;

        static void Main(string[] args) {
            Console.WriteLine("\n Crypto pals challenges output:");
            Console.WriteLine("--------------------------------\n");

            bool result = challenge27();

            Console.WriteLine("\n--------------------------------");
            Console.WriteLine(result ? " SUCCESS!" : " FAIL!");
            Console.ReadLine();
        }

        // Break CBC key where IV = Key
        static bool challenge27() {
            const int blocksize = 16;

            byte[] input = Helpers.RandomByteArray(60); // long enough
            byte[] cipher = encryptionOracle27(input);

            byte[] firstBlock = Helpers.CopyPartOf(cipher, 0, blocksize);
            Array.Copy(new byte[blocksize], 0, cipher, blocksize, blocksize);
            Array.Copy(firstBlock, 0, cipher, 2 * blocksize, blocksize);

            try {
                decryptionOracle27(cipher);
            }
            catch (Exception e) {
                byte[] decryption = Helpers.FromHexString(e.Message);
                firstBlock = Helpers.CopyPartOf(decryption, 0, blocksize);
                byte[] thirdBlock = Helpers.CopyPartOf(decryption, 2 * blocksize, blocksize);

                byte[] key = Helpers.XOR(firstBlock, thirdBlock);
                Helpers.PrintHexString("Key: ", key);
                return Helpers.Equals(key, fixedKey);
            }

            Console.WriteLine("No high ascii values after modifying the cipher o_O");
            return false;
        }

        static byte[] encryptionOracle27(byte[] input) {
            // CBC encrypt with IV = key
            const int blocksize = 16;
            if (fixedKey == null)
                fixedKey = Helpers.RandomByteArray(blocksize);

            string userData = Helpers.ToUTF8String(input);
            KeyValuePairs cookie = KeyValuePairs.CookingUserdata(userData);
            string url = cookie.ToUrl();
            return BlockCipher.EncryptAES(Helpers.FromUTF8String(url), fixedKey, fixedKey, CipherMode.CBC, PaddingMode.PKCS7);
        }

        static bool decryptionOracle27(byte[] cipher) {
            byte[] original = BlockCipher.DecryptAES(cipher, fixedKey, fixedKey, CipherMode.CBC, PaddingMode.None);
            byte[] plain = unPKCS7(original);

            // If the plain contains high ascii values, return exception with the (decrypted) plaintext
            if (plain.Any(b => b > (int)'z' + 20))
                throw new Exception(Helpers.ToHexString(plain));

            KeyValuePairs cookie = KeyValuePairs.FromURL(Helpers.ToUTF8String(plain));
            return cookie["admin"] == "true";
        }

        // Modify a CTR encrypted cookie (bitflipping)
        static bool challenge26() {
            string userdata = "---4---8---4---8" + "_admin_true";
            BlockCipherResult cipherAndNonce = encryptionOracle26(Helpers.FromUTF8String(userdata));
            byte[] cipher = cipherAndNonce.Cipher;

            // index of first '_' char is: 8 + 1 + 14 + 1 + 8 + 1 + 16 = 49
            byte[] xors = new byte[cipher.Length];
            byte _ = Helpers.FromUTF8Char('_');
            byte and = Helpers.FromUTF8Char('&');
            byte eq = Helpers.FromUTF8Char('=');
            xors[49] = (byte)(_ ^ and);
            xors[49 + 6] = (byte)(_ ^ eq);

            cipher = Helpers.XOR(cipher, xors);
            cipherAndNonce.Cipher = cipher;

            return decryptionOracle26(cipherAndNonce);
        }

        static BlockCipherResult encryptionOracle26(byte[] input) {
            const int blocksize = 16;

            byte[] nonce = Helpers.RandomByteArray(8);
            if (fixedKey == null)
                fixedKey = Helpers.RandomByteArray(blocksize);

            string userData = Helpers.ToUTF8String(input);
            var cookie = KeyValuePairs.CookingUserdata(userData);
            byte[] urlBytes = Helpers.FromUTF8String(cookie.ToUrl());

            return BlockCipher.Result(encryptOrDecryptAesCtr(urlBytes, fixedKey, nonce), nonce);
        }

        static bool decryptionOracle26(BlockCipherResult cipherAndNonce) {
            byte[] plain = encryptOrDecryptAesCtr(cipherAndNonce, fixedKey);

            var cookie = KeyValuePairs.FromURL(Helpers.ToUTF8String(plain));
            return cookie["admin"] == "true";
        }

        // Break 'random access read/write' AES CTR
        static bool challenge25() {
            BlockCipherResult cipherAndNonce = encryptionOracle25();
            byte[] cipher = cipherAndNonce.Cipher;
            byte[] plain = new byte[cipher.Length];

            Console.WriteLine("Decrypting ({0} bytes)", cipher.Length);
            unchecked {
                for (int i = 0; i < cipher.Length; i++) {
                    for (int newPlainByte = 0; newPlainByte < 256; newPlainByte++) {
                        byte newCipherByte = editOracle(cipherAndNonce, i, (byte)newPlainByte)[i];
                        if (newCipherByte == cipher[i]) {
                            plain[i] = (byte)newPlainByte;
                            newPlainByte = 256;
                        }
                    }

                    if (i % 100 == 0)
                        Console.Write('.');
                }
            }
            Console.WriteLine('\n');

            Helpers.PrintUTF8String(plain);

            return Helpers.QuickCheck(plain, 2880, "I'm back and I'm ringin' the bell");
        }

        static BlockCipherResult encryptionOracle25() {
            byte[] input = Helpers.ReadBase64File("Data/25.txt"); // Encrypted input from challenge 7
            byte[] key = Helpers.FromUTF8String("YELLOW SUBMARINE");
            input = BlockCipher.DecryptAES(input, key, null, CipherMode.ECB, PaddingMode.PKCS7);

            byte[] nonce = Helpers.RandomByteArray(8);
            if (fixedKey == null)
                fixedKey = Helpers.RandomByteArray(16);

            byte[] cipher = encryptOrDecryptAesCtr(input, fixedKey, nonce);
            return BlockCipher.Result(cipher, nonce);
        }

        static byte[] editOracle(BlockCipherResult cipherAndNonce, int offset, byte replacement) {
            // Optimized version for changing 1 byte only
            const int blocksize = 16;
            const int halfBlocksize = blocksize / 2;

            // Generate the keystream for the block the new plain byte is in
            byte[] result = Helpers.Copy(cipherAndNonce.Cipher);
            int counter = offset / blocksize;
            int blockStart = counter * blocksize;
            byte[] block = Helpers.CopyPartOf(cipherAndNonce.Cipher, blockStart, blocksize);

            byte[] nonceAndCounter = new byte[blocksize];
            Array.Copy(cipherAndNonce.Iv, nonceAndCounter, halfBlocksize);
            Array.Copy(Helpers.LittleEndian((ulong)counter), 0, nonceAndCounter, halfBlocksize, halfBlocksize);

            byte[] keystream = BlockCipher.EncryptAES(nonceAndCounter, fixedKey, null, CipherMode.ECB, PaddingMode.None);

            // Change the old plain byte
            block = Helpers.XOR(block, keystream);
            block[offset - blockStart] = replacement;
            block = Helpers.XOR(block, keystream);

            Array.Copy(block, 0, result, blockStart, Math.Min(result.Length - blockStart, blocksize));
            return result;
        }
        static byte[] editOracle(BlockCipherResult cipherAndNonce, int offset, byte[] replacement) {
            byte[] plain = encryptOrDecryptAesCtr(cipherAndNonce, fixedKey);
            byte[] result = new byte[Math.Max(cipherAndNonce.Length, offset + replacement.Length)];
            Array.Copy(plain, result, plain.Length);
            Array.Copy(replacement, 0, result, offset, replacement.Length);
            return encryptOrDecryptAesCtr(result, fixedKey, cipherAndNonce.Iv);
        }

        #region Set 3

        // Run all challenges of set 2
        static bool runSet3() {
            bool result = true;

            Console.WriteLine("Challenge 17:");
            result &= challenge17();
            Console.WriteLine("\nChallenge 18:");
            result &= challenge18();
            Console.WriteLine("\nChallenge 19:");
            result &= challenge19();
            Console.WriteLine("\nChallenge 20:");
            result &= challenge20();
            Console.WriteLine("\nChallenge 21:");
            result &= challenge21();
            Console.WriteLine("\nChallenge 22:");
            result &= challenge22(false);
            Console.WriteLine("\nChallenge 23:");
            result &= challenge23();
            Console.WriteLine("\nChallenge 24:");
            result &= challenge24();

            return result;
        }

        // Create the MT19937 stream cipher and break it
        static bool challenge24() {
            // Part 1. Create the MT19937 stream cipher
            byte[] input = Helpers.FromUTF8String("Test input");
            byte[] key = Helpers.RandomByteArray(2);
            uint nonce = Helpers.ToUInt(Helpers.RandomByteArray(2));

            byte[] cipher = encryptOrDecryptMt19937(input, key, nonce);
            byte[] backToInput = encryptOrDecryptMt19937(cipher, key, nonce);

            if (!Helpers.Equals(backToInput, input)) {
                Helpers.PrintUTF8String(backToInput);
                return false;
            }

            // Part 2. Decrypt a known plaintext (prefixed with some random chars) and crack the key
            key = new byte[2];
            input = Helpers.FromUTF8String("AAAAAAAAAAAAAA");
            BlockCipherResult cipherAndNonce = encryptionOracle24(input);
            cipher = cipherAndNonce.Cipher;
            int nrOfPrefixBytes = cipher.Length - input.Length;
            byte[] prefixedInput = new byte[cipher.Length];
            Array.Copy(input, 0, prefixedInput, nrOfPrefixBytes, input.Length);
            byte[] nonceBytes = cipherAndNonce.Iv;
            byte[] keyStream = Helpers.XOR(prefixedInput, cipher);

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
                        Console.WriteLine("The seed: {0}", Helpers.ToHexString(k));
                    }
            }
            byte[] cipher2 = encryptOrDecryptMt19937(prefixedInput, key, Helpers.ToUInt(nonceBytes));
            Array.Copy(cipher, cipher2, nrOfPrefixBytes); // I don't know the random bytes, so I'l cheat a bit
            if (!Helpers.Equals(cipher2, cipher)) {
                Console.WriteLine("Failed part 2");
                return false;
            }

            // Part 3. Generate and check for a random password token
            Console.WriteLine();
            uint startTimeStamp = Helpers.UnixTimeU();
            string token = randomPasswordToken();
            Console.WriteLine(token);
            uint endTimeStamp = Helpers.UnixTimeU();

            bool tokenIsMtFromCurrentTime = false;
            for (uint t = startTimeStamp; t <= endTimeStamp; t++)
                if (token == randomPasswordToken(t)) {
                    tokenIsMtFromCurrentTime = true;
                    Console.WriteLine("This token is generated with seed {0}, which is the current timestamp.", t);
                }

            return tokenIsMtFromCurrentTime;
        }

        static string randomPasswordToken(uint? seed = null, int nrOfBytes = 25) {
            var mt = new MersenneTwister(seed ?? Helpers.UnixTimeU());
            byte[] result = mt.NextBytes(nrOfBytes);

            return Helpers.ToTokenString(result, nrOfBytes);
        }

        static BlockCipherResult encryptionOracle24(byte[] input) {
            if (fixedKey == null)
                fixedKey = new byte[2];
            byte[] randomPrefix = Helpers.RandomByteArray(Helpers.Random.Next(10, 20));
            fixedKey = Helpers.RandomByteArray(2);
            uint nonce = Helpers.ToUInt(Helpers.RandomByteArray(2));
            byte[] result = encryptOrDecryptMt19937(Helpers.Concatenate(randomPrefix, input), fixedKey, nonce);
            return BlockCipher.Result(result, Helpers.LittleEndian(nonce));
        }

        static byte[] encryptOrDecryptMt19937(byte[] input, byte[] key, uint nonce) {
            const int uintsize = 4;

            // Init the MT
            byte[] seed = new byte[uintsize];
            Array.Copy(key, seed, uintsize / 2);
            Array.Copy(Helpers.LittleEndian(nonce), 0, seed, uintsize / 2, uintsize / 2);
            var mt = new MersenneTwister(seed);

            // Generate the keystream
            byte[] keystream = mt.NextBytes(input.Length);

            return Helpers.XOR(input, keystream);
        }

        // Clone a MT19937 RNG from its output
        static bool challenge23() {
            // The 'original' RNG
            MersenneTwister mt = new MersenneTwister(Helpers.UnixTimeU()); // secret enough xD

            // Get the state
            var state = new uint[624];
            for (int i = 0; i < state.Length; i++)
                state[i] = MersenneTwister.Untemper(mt.Next());

            // Clone a new RNG
            MersenneTwister clonedMt = new MersenneTwister(state);

            // Output
            uint nextCloned = clonedMt.Next();
            uint nextOriginal = mt.Next();
            Console.WriteLine("Predicted next random number: {0}", Helpers.ToBitString(nextCloned));
            Console.WriteLine("Next random number:           {0}", Helpers.ToBitString(nextOriginal));

            // @Stop and think: the problem here is the invertability of the tampering.
            // If you use hashes, that's no longer possible, but the rng would become A LOT slower.
            return nextOriginal == nextCloned;
        }

        // Crack an MT19937 seeded on current timestamp
        static bool challenge22(bool hardMode = true) {
            // Send the request (and measure the begin and end times)
            Console.WriteLine("Sending the 'request'...");
            uint startTimestamp = Helpers.UnixTimeU();
            uint randomNumber = getRandom22(hardMode);
            uint finishTimestamp = Helpers.UnixTimeU();
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

            Thread.Sleep(Helpers.Random.Next(min * factor, max * factor));
            MersenneTwister mt = new MersenneTwister(Helpers.UnixTimeU());
            Thread.Sleep(Helpers.Random.Next(min * factor, max * factor));

            return mt.Next();
        }

        // Implement the mersenne twister (MT19937)
        static bool challenge21() {
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

            return Helpers.Equals(generatedValues, expectedValues);
        }

        // Break fixed nonce CTR statistically (frequency analysis)
        static bool challenge20() {
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
                attackSingleXOR(merged, scoreList);

                keystream[i] = scoreList.Last().KeyUsed.First();
            }

            // Print the result
            foreach (byte[] cipher in input)
                Helpers.PrintUTF8String(Helpers.XOR(cipher, keystream));

            byte[] lastLine = Helpers.XOR(input.Last(), keystream);
            return Helpers.QuickCheck(lastLine, 55, "And we outta here / Yo, what happened to peace? / Peace");
        }

        static List<byte[]> encrypt20() {
            fixedKey = Helpers.FromHexString("0x41BDFD6EDEC769B61A7815447D9DB6F1"); // Randomly generated, but fixed
            ulong nonce = 0;

            List<byte[]> result = new List<byte[]>(40);
            using (StreamReader reader = new StreamReader("Data/20.txt")) {
                string line;
                while ((line = reader.ReadLine()) != null) {
                    byte[] raw = Convert.FromBase64String(line);
                    raw = encryptOrDecryptAesCtr(raw, fixedKey, nonce);
                    result.Add(raw);
                }
            }
            return result;
        }

        // Break fixed nonce CTR using frequency analysis (and some substitutions)
        static bool challenge19() {
            // Helpers.PrintAsciiTable();

            List<byte[]> ciphers = encrypt19();
            byte[] keystreamSoFar = Helpers.FromHexString(
                "0x4838344276FE8B4E949618FE4EBF52F5A2AE678AA250F263A52DCD2688671E2D955373197343"
            );

            // Determine the size of the keystream we want to crack
            int keystreamSize = 38;
            keystreamSize = Math.Max(keystreamSize, keystreamSoFar.Length);
            var longCiphers = ciphers.Where(c => c.Length >= keystreamSize).ToList();

            // Merge them into one gigantic array and give them to the repeating XOR attacker from challenge 6
            var temp = new List<byte>();
            foreach (byte[] cipher in longCiphers)
                temp.AddRange(Helpers.CopyPartOf(cipher, 0, keystreamSize));
            byte[] merged = temp.ToArray();

            byte[] keystream = attackRepeatingXOR(merged, keystreamSize, keystreamSoFar);

            // Print the results for this key
            Console.WriteLine("Keystream size: {0} (max: {1}), #ciphers left: {2}",
                keystreamSize, ciphers.Max(c => c.Length), longCiphers.Count);
            Helpers.PrintHexString(keystream);
            Console.WriteLine();

            // foreach (var cipher in longCiphers.Take(10)) {
            //     byte[] part = Helpers.CopyPartOf(cipher, 0, keystreamSize);
            //     Helpers.PrintUTF8String(Helpers.XOR(part, keystream));
            // }

            // Now I'm done, let's print all the strings
            Console.WriteLine("\n\nAll decrypted strings:\n");
            foreach (var c in ciphers)
                Helpers.PrintUTF8String(Helpers.XOR(c, keystreamSoFar));

            return Helpers.Equals(
                Helpers.FromHexString("0x4838344276FE8B4E949618FE4EBF52F5A2AE678AA250F263A52DCD2688671E2D955373197343"),
                keystream
            );
        }

        static List<byte[]> encrypt19() {
            fixedKey = Helpers.FromHexString("0x6CA0AF24369C8531BE2C7AE3AB8DBEA4"); // Randomly generated, but fixed
            ulong nonce = 0;

            List<byte[]> result = new List<byte[]>(40);
            using (StreamReader reader = new StreamReader("Data/19.txt")) {
                string line;
                while ((line = reader.ReadLine()) != null) {
                    byte[] raw = Convert.FromBase64String(line);
                    raw = encryptOrDecryptAesCtr(raw, fixedKey, nonce);
                    result.Add(raw);
                }
            }
            return result;
        }

        // Implement CTR mode of AES
        static bool challenge18() {
            int blocksize = 16;
            byte[] input = Convert.FromBase64String("L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==");
            byte[] key = Helpers.FromUTF8String("YELLOW SUBMARINE");
            ulong nonce = 0;

            byte[] result = encryptOrDecryptAesCtr(input, key, nonce);
            byte[] backToInput = encryptOrDecryptAesCtr(result, key, nonce);

            string test = Helpers.ToUTF8String(unPKCS7(result));
            Helpers.PrintUTF8String(unPKCS7(result));

            return Helpers.QuickCheck(result, input.Length, "Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby")
                && Helpers.Equals(input, backToInput);
        }

        static byte[] encryptOrDecryptAesCtr(byte[] input, byte[] key, ulong nonce) {
            return encryptOrDecryptAesCtr(input, key, Helpers.LittleEndian(nonce));
        }
        static byte[] encryptOrDecryptAesCtr(BlockCipherResult cipherAndNonce, byte[] key) {
            return encryptOrDecryptAesCtr(cipherAndNonce.Cipher, key, cipherAndNonce.Iv);
        }
        static byte[] encryptOrDecryptAesCtr(byte[] input, byte[] key, byte[] nonce) {
            const int blocksize = 16;
            const int halfBlocksize = blocksize / 2;
            byte[] result = new byte[input.Length];
            byte[] nonceAndCounter = new byte[blocksize];
            ulong counter = 0;

            for (int i = 0; i < input.Length; i += blocksize) {
                byte[] block = Helpers.CopyPartOf(input, i, blocksize);

                Array.Copy(nonce, nonceAndCounter, halfBlocksize);
                Array.Copy(Helpers.LittleEndian(counter), 0, nonceAndCounter, halfBlocksize, halfBlocksize);

                byte[] keystream = BlockCipher.EncryptAES(nonceAndCounter, key, null, CipherMode.ECB, PaddingMode.None);

                block = Helpers.XOR(block, keystream);
                Array.Copy(block, 0, result, i, Math.Min(result.Length - i, blocksize));

                counter++;
            }

            return result;
        }

        // Decrypt a random CBC encrypted string, using a CBC padding oracle
        static bool challenge17() {
            int blocksize = 16;
            // The idea is to tamper the ciphertext in the following way:
            // - xor out the guessed byte (only if guessed right of course) and then xor in the new padding (say, 0x01).
            // - Check it's padding; if that padding is valid: then the last byte is, with high probability, 0x01,
            //   so our guess was right and we know a byte of the input.

            // Get the encrypted string we want to decrypt
            BlockCipherResult original = encryptionOracle17();
            byte[] answer = new byte[original.Cipher.Length];
            Console.Write("Cipher hex:   ");
            Helpers.PrintHexString(original.Cipher);

            for (int index = answer.Length - 1; index >= 0; index--) {
                // Setup for breaking the index-th byte
                int paddingbyte = blocksize - (index % blocksize);
                byte[] cipher = Helpers.CopyPartOf(original.Cipher, 0, Helpers.ClosestMultipleHigher(index + 1, blocksize));
                byte[] iv = Helpers.Copy(original.Iv);

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
            Helpers.PrintHexString(answer);
            Console.Write("Answer UTF-8: ");
            Helpers.PrintUTF8String(unPKCS7(answer));

            return Helpers.Equals(Convert.FromBase64String("MDAw"), Helpers.CopyPartOf(answer, 0, 3));
        }

        static BlockCipherResult encryptionOracle17() {
            int blocksize = 16;

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
            byte[] plain = Convert.FromBase64String(sources[Helpers.Random.Next(10)]);

            // Generate a random (so unknown) key and use it throughout the rest of the program
            if (fixedKey == null)
                fixedKey = Helpers.RandomByteArray(blocksize);

            // Generate a random iv and encrypt the chosen plaintext
            byte[] iv = Helpers.RandomByteArray(blocksize);
            byte[] cipher = BlockCipher.EncryptAES(plain, fixedKey, iv, CipherMode.CBC, PaddingMode.PKCS7);

            return BlockCipher.Result(cipher, iv);
        }

        static bool paddingOracle17(byte[] cipher, byte[] iv) {
            // Return true or false depending on whether or not the padding is correct
            byte[] plain = BlockCipher.DecryptAES(cipher, fixedKey, iv, CipherMode.CBC, PaddingMode.None);
            return checkPKCS7(plain);
        }

        #endregion

        #region Set 2

        // Run all challenges of set 2
        static bool runSet2() {
            bool result = true;

            Console.WriteLine("Challenge 9:");
            result &= challenge9();
            Console.WriteLine("\nChallenge 10:");
            result &= challenge10();
            Console.WriteLine("\nChallenge 11:");
            result &= challenge11();
            Console.WriteLine("\nChallenge 12:");
            result &= challenge12();
            Console.WriteLine("\nChallenge 13:");
            result &= challenge13();
            Console.WriteLine("\nChallenge 14:");
            result &= challenge14();
            Console.WriteLine("\nChallenge 15:");
            result &= challenge15();
            Console.WriteLine("\nChallenge 16:");
            result &= challenge16();

            return result;
        }

        // Modify a CBC encrypted cookie (bitflipping)
        static bool challenge16() {
            // The goal again is to modify the (AES-123 CBC encrypted) cookie and slip an admin=true inside
            // Input:   Number of bytes in the cookie string before our content: 8+1+13+1+8+1 = 32 bytes prepending data (exactly 2 blocks, easy for us)
            //          Number of bytes for the "&admin=true" string: 1+5+1+4 = 11 bytes

            // Plan: insert some random userdata (1 block) and then insert the &admin=true, but without the = and & signs.
            // Then afterwards we modify the ciphertext of the first block of 'userdata' so that the = and & signs will be XOR-ed in.
            string userdata = "---4---8---4---8" + "_admin_true";
            byte[] cipher = encryptionOracle16(Helpers.FromUTF8String(userdata));

            byte[] xors = new byte[cipher.Length];
            byte _ = Helpers.FromUTF8Char('_');
            byte and = Helpers.FromUTF8Char('&');
            byte eq = Helpers.FromUTF8Char('=');
            xors[33] = (byte)(_ ^ and);
            xors[39] = (byte)(_ ^ eq);

            cipher = Helpers.XOR(cipher, xors);

            return decryptionOracle16(cipher);
        }

        static byte[] encryptionOracle16(byte[] input) {
            // Emulate a function at the server to cook some userData like a pound of bacon
            const int blocksize = 16;

            // Generate a random (so unknown) key and use it throughout the rest of the program
            if (fixedKey == null)
                fixedKey = Helpers.RandomByteArray(blocksize);

            // Generate cookie and encrypt it
            string userData = Helpers.ToUTF8String(input);
            KeyValuePairs cookie = KeyValuePairs.CookingUserdata(userData);
            string url = cookie.ToUrl();
            return BlockCipher.EncryptAES(Helpers.FromUTF8String(url), fixedKey, new byte[blocksize], CipherMode.CBC, PaddingMode.PKCS7);
        }

        static bool decryptionOracle16(byte[] cipher) {
            // Check the cookie for admin access
            const int blocksize = 16;

            // Decrypt the cookie
            byte[] original = BlockCipher.DecryptAES(cipher, fixedKey, new byte[blocksize], CipherMode.CBC, PaddingMode.None);
            byte[] plain = unPKCS7(original);

            // Check for admin rights
            KeyValuePairs cookie = KeyValuePairs.FromURL(Helpers.ToUTF8String(plain));
            return cookie["admin"] == "true";
        }

        // Remove PKCS#7 padding, with exception if it fails
        static bool challenge15() {
            // Input:  "ICE ICE BABY\x04\x04\x04\x04", "ICE ICE BABY\x05\x05\x05\x05", "ICE ICE BABY\x01\x02\x03\x04"
            // Answer: "ICE ICE BABY", exception, exception
            bool exception1 = false, exception2 = false;

            string result = Helpers.ToUTF8String(unPKCS7(Helpers.FromUTF8String("ICE ICE BABY\x04\x04\x04\x04")));
            Console.WriteLine(result);

            if (!checkPKCS7(Helpers.FromUTF8String("ICE ICE BABY\x05\x05\x05\x05"))) {
                exception1 = true;
                Console.WriteLine("Bad padding");
            }

            if (!checkPKCS7(Helpers.FromUTF8String("ICE ICE BABY\x01\x02\x03\x04"))) ;
            {
                exception2 = true;
                Console.WriteLine("Bad padding");
            }

            return result == "ICE ICE BABY" && exception1 && exception2;
        }

        // Byte at a time ECB decryption (hard)
        static bool challenge14() {
            // Input:  Same as challenge 12, but now with a slightly modified oracle

            // Detect blocksize and cipher mode (16 bytes, ECB)
            int messageLength;
            int blocksize = findOracleBlockSize(encryptionOracle14, out messageLength);
            bool modeIsECB = oracleUsesECB(encryptionOracle14);

            // Determine the length of the random prefix (this is the new part)
            int inversePrefixLength = 0, totalPrefixLength = 0;
            byte[] cipher, input;
            for (int i = 0; i < blocksize; i++) {
                int equalBlocks = 5;
                input = new byte[i + equalBlocks * blocksize];
                cipher = encryptionOracle14(input);
                byte[][] cipherBlocks = Helpers.SplitUp(cipher, blocksize);

                bool foundPrefixLength = false;
                for (int j = 0; j < cipherBlocks.Length - equalBlocks; j++) {
                    foundPrefixLength = true;
                    for (int k = equalBlocks - 1; k >= 1; k--) {
                        if (!Helpers.Equals(cipherBlocks[j], cipherBlocks[j + k])) {
                            foundPrefixLength = false;
                            break;
                        }
                    }
                    if (foundPrefixLength) {
                        inversePrefixLength = i;
                        totalPrefixLength = j * blocksize;
                        break;
                    }
                }
                if (foundPrefixLength) {
                    break;
                }
            }

            // Summarize findings so far
            Console.WriteLine("Blocksize: " + blocksize.ToString() + " bytes, messageLength: " + messageLength.ToString() + " bytes, mode: " + (modeIsECB ? "ECB" : "Unknown"));
            Console.WriteLine("inversePrefixLength: " + inversePrefixLength.ToString() + ", totalPrefixLength: " + totalPrefixLength.ToString() + "\n");

            // Decrypt the message inside the oracle
            byte[] result = new byte[messageLength - totalPrefixLength + inversePrefixLength];
            byte[][] lookupTable;
            for (int hackPosition = 0; hackPosition < result.Length; hackPosition++) { // The (position of the) byte we are going to decrypt
                                                                                       // Build the lookup table
                lookupTable = new byte[256][];
                for (int b = 0; b < 256; b++) {
                    // Recreate the input for the current block to analyze
                    input = new byte[inversePrefixLength + blocksize];
                    for (int i = 1; i <= hackPosition && i < blocksize; i++)
                        input[input.Length - i - 1] = result[hackPosition - i];                 // Copy the part of the text we already decrypted (well, the last #blocksize part, padded with zeroes to the front)
                    input[input.Length - 1] = (byte)b;                                          // Try all values for the last byte (the one we don't know yet)
                    cipher = encryptionOracle14(input);                                         // Now feed it to the oracle
                    lookupTable[b] = Helpers.CopyPartOf(cipher, totalPrefixLength, blocksize);  // And there we have all possible encryptions if the block is being feeded to the oracle such that the unknown byte is at the back
                }
                // Lookup the value of the byte to crack
                int offset = hackPosition / blocksize * blocksize;
                input = new byte[inversePrefixLength + blocksize - hackPosition + offset - 1];
                cipher = Helpers.CopyPartOf(encryptionOracle14(input), totalPrefixLength + offset, blocksize);
                for (int b = 0; b < 256; b++)
                    if (Helpers.Equals(lookupTable[b], cipher)) {
                        result[hackPosition] = (byte)b;
                        break;
                    }
            }

            // The decrypted message
            Helpers.PrintUTF8String(result);

            return Helpers.QuickCheck(result, 138, "Rollin' in my 5.0");
        }

        static byte[] encryptionOracle14(byte[] input) {
            // This function takes an input and encrypts it with a fixed unknown key (fixedKey)
            int blocksize = 16;

            // Generate a random (so unknown) key and use it throughout the rest of the program
            if (fixedKey == null) {
                fixedKey = Helpers.RandomByteArray(blocksize);
                fixedBytes = Helpers.RandomByteArray(Helpers.Random.Next(5, 55));
            }

            // The plaintext to encrypt will be [random_prefix + input + secret message] (the secret message that we want to decrypt)
            byte[] secretMessage = Convert.FromBase64String(
                "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg"
                + "aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq"
                + "dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg"
                + "YnkK");
            byte[] plain = Helpers.Concatenate(fixedBytes, input, secretMessage);

            // Encrypt and return
            return BlockCipher.EncryptAES(plain, fixedKey, null, CipherMode.ECB, PaddingMode.PKCS7);
        }

        // ECB cut-and-paste
        static bool challenge13() {
            // The goal is to create a valid (but encrypted) user profile cookie, then replace the "role=user" to "role=admin" and feed it to the server, who will decrypt it with the hacked role
            // Input:  -

            // This hack depends on the order being 'email', 'uid', 'role' - especially important is the 'role' part being at the end of the block
            // I am also assuming I know the exact format of input and output, although I could just find that by decrypting some ECB'ed email-inputs a few times.
            // (This would be nescessary to determine the order of magnitude of the uid, but I happen to know that it's one digit :P).

            // The outline of the attack:
            // First try: email=AAAAAAAAAAadmin___________@gmail.com&uid=0&role=user       (where _'s are determined by padding)
            //            ...-...-...-...|...-...-...-...|...-...-...-...|...-...-...-...|
            // Now the second block is the encrypted version of the padded word admin
            // Second try: email=AAAA@gmail.com&uid=1&role=user
            //             ...-...-...-...|...-...-...-...|...-...-...-...|
            // And now we replace the third block with our word admin, and there we have our cut 'n pasted message

            // First try
            int blocksize = 16;
            byte[] before = Helpers.FromUTF8String("AAAAAAAAAA");
            byte[] adminWord = PKCS7(Helpers.FromUTF8String("admin"), blocksize);
            byte[] after = Helpers.FromUTF8String("@gmail.com");
            byte[] input = Helpers.Concatenate(before, adminWord, after);
            byte[] cipher = encryptionOracle13(input);
            byte[] encryptedAdminWord = Helpers.CopyPartOf(cipher, blocksize, blocksize);

            // Second try
            input = Helpers.FromUTF8String("AAAA@gmail.com");
            cipher = encryptionOracle13(input);
            before = Helpers.CopyPartOf(cipher, 0, 2 * blocksize);
            byte[] encryptedResult = Helpers.Concatenate(before, encryptedAdminWord);

            // Lets 'send' our hacked cookie back to the server and print here what the server would see
            byte[] result = BlockCipher.DecryptAES(encryptedResult, fixedKey, null, CipherMode.ECB, PaddingMode.PKCS7);
            Helpers.PrintUTF8String(result);

            return Helpers.QuickCheck(result, 3 * blocksize, "email=AAAA@gmail.com&uid=1&role=admin");
        }

        static byte[] encryptionOracle13(byte[] email) {
            // Emulate a function at the server to generate a valid encrypted cookie
            int blocksize = 16;

            // Generate a random (so unknown) key and use it throughout the rest of the program
            if (fixedKey == null) {
                fixedKey = Helpers.RandomByteArray(blocksize);
            }

            // Generate cookie and encrypt it
            string emailAddress = Helpers.ToUTF8String(email);
            KeyValuePairs cookie = KeyValuePairs.ProfileFor(emailAddress);
            string url = cookie.ToUrl();
            return BlockCipher.EncryptAES(Helpers.FromUTF8String(url), fixedKey, null, CipherMode.ECB, PaddingMode.PKCS7);
        }

        // Byte at a time ECB decription (simple) - Break AES in ECB mode o_O
        static bool challenge12() {
            // Input:  Some unknown base64 string: (this is the plaintext that we need to crack - it is used inside the 'secret' ECB oracle)
            //         Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
            //         aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
            //         dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
            //         YnkK

            // Detect blocksize and cipher mode (16 bytes, ECB)
            int messageLength;
            int blocksize = findOracleBlockSize(encryptionOracle12, out messageLength);
            bool modeIsECB = oracleUsesECB(encryptionOracle12);
            Console.WriteLine("Blocksize: " + blocksize.ToString() + " bytes, messageLength: " + messageLength.ToString() + " bytes, mode: " + (modeIsECB ? "ECB" : "Unknown") + "\n");

            // Decrypt the message inside the oracle
            byte[] result = new byte[messageLength];
            byte[] cipher, input;
            byte[][] lookupTable;
            for (int hackPosition = 0; hackPosition < result.Length; hackPosition++) { // The (position of the) byte we are going to decrypt
                                                                                       // Build the lookup table
                lookupTable = new byte[256][];
                for (int b = 0; b < 256; b++) {
                    // Recreate the input for the current block to analyze
                    input = new byte[blocksize];
                    for (int i = 1; i <= hackPosition && i < blocksize; i++)
                        input[input.Length - i - 1] = result[hackPosition - i]; // Copy the part of the text we already decrypted (well, the last #blocksize part, padded with zeroes to the front)
                    input[input.Length - 1] = (byte)b;                          // Try all values for the last byte (the one we don't know yet)
                    cipher = encryptionOracle12(input);                         // Now feed it to the oracle
                    lookupTable[b] = Helpers.CopyPartOf(cipher, 0, blocksize);  // And there we have all possible encryptions if the block is being feeded to the oracle such that the unknown byte is at the back
                }
                // Lookup the value of the byte to crack
                int offset = hackPosition / blocksize * blocksize;
                input = new byte[blocksize - hackPosition + offset - 1];
                cipher = Helpers.CopyPartOf(encryptionOracle12(input), offset, blocksize);
                for (int b = 0; b < 256; b++)
                    if (Helpers.Equals(lookupTable[b], cipher)) {
                        result[hackPosition] = (byte)b;
                        break;
                    }
            }

            // The decrypted message
            Helpers.PrintUTF8String(result);

            return Helpers.QuickCheck(result, 138, "Rollin' in my 5.0");
        }

        static int findOracleBlockSize(Func<byte[], byte[]> oracleFunction, out int messageLength) {
            // Return the block size (and message length) of an oracle function
            byte[] input = new byte[0];
            int initialLength = oracleFunction(input).Length;
            for (int i = 0; i < 9999; i++) {
                input = new byte[input.Length + 1];
                int tempLength = oracleFunction(input).Length;
                if (tempLength != initialLength) {
                    messageLength = initialLength - i - 1;
                    return tempLength - initialLength;
                }
            }
            throw new Exception("The oracle has no distinguishable blocksize in 10k tries");
        }

        static byte[] encryptionOracle12(byte[] input) {
            // This function takes an input and encrypts it with a fixed unknown key (fixedKey)
            int blocksize = 16;

            // Generate a random (so unknown) key and use it throughout the rest of the program
            if (fixedKey == null)
                fixedKey = Helpers.RandomByteArray(blocksize);

            // The plaintext to encrypt will be [input + secret message] (the secret message that we want to decrypt)
            byte[] secretMessage = Convert.FromBase64String(
                "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg"
                + "aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq"
                + "dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg"
                + "YnkK");
            byte[] plain = Helpers.Concatenate(input, secretMessage);

            // Encrypt and return
            return BlockCipher.EncryptAES(plain, fixedKey, null, CipherMode.ECB, PaddingMode.PKCS7);
        }

        // An ECB/CBC detection oracle
        static bool challenge11() {
            // The goal is to write something that given a black box, that it detects whether it encrypts with ECB or CBC
            // Input:  -

            Console.WriteLine("Whether or not the oracle used ECB mode or not (CBC mode)");
            for (int i = 0; i < 10; i++)
                Console.WriteLine("  ECB detected: " + oracleUsesECB(randomECB_CBCEncryptionOracle).ToString());

            return true;
        }

        static bool oracleUsesECB(Func<byte[], byte[]> oracleFunction) {
            // Detect whether or not the function encrypted using ECB mode
            int blocksize = 16;
            int blocks = 6;

            byte[] input = new byte[blocks * blocksize]; // input some blocks with only zeroes - at least 5 of them should give equal blocks after encryption with ECB
            byte[][] cipherBlocks = Helpers.SplitUp(oracleFunction(input), blocksize);

            int equalBlocks = 1;
            for (int i = 0; i < cipherBlocks.Length - 1; i++)
                if (Helpers.Equals(cipherBlocks[i], cipherBlocks[i + 1]))
                    equalBlocks++;

            return equalBlocks >= blocks - 1;
        }

        static byte[] randomECB_CBCEncryptionOracle(byte[] input) {
            // This function takes an input and encrypts it randomly with ECB or CBC. It also adds random bytes before and after the input array.

            // Initialize
            byte[] key = Helpers.RandomByteArray(16);
            byte[] before = Helpers.RandomByteArray(Helpers.Random.Next(5, 11));
            byte[] after = Helpers.RandomByteArray(Helpers.Random.Next(5, 11));
            byte[] iv = null;

            // Create the result array with the original and generated input
            byte[] result = Helpers.Concatenate(before, key, after);

            // Encrypt the result array
            if (Helpers.Random.Next(2) == 0) {
                // ECB
                Console.WriteLine("The encryption oracle secretly used ECB mode... ");
                result = BlockCipher.EncryptAES(result, key, null, CipherMode.ECB, PaddingMode.PKCS7);
            }
            else {
                // CBC
                Console.WriteLine("The encryption oracle secretly used CBC mode... ");
                iv = Helpers.RandomByteArray(key.Length);
                result = BlockCipher.EncryptAES(result, key, iv, CipherMode.CBC, PaddingMode.PKCS7);
            }
            return result;
        }

        // Implement CBC mode of AES
        static bool challenge10() {
            // Input:  The base64 encoded content of file Data/10.txt
            //         The key is: "YELLOW SUBMARINE"
            //         The IV consists of all ASCII 0 charachters ("\x00\x00\x00...")

            byte[] input = Helpers.ReadBase64File("Data/10.txt");
            byte[] key = Helpers.FromUTF8String("YELLOW SUBMARINE");
            byte[] iv = new byte[key.Length];

            byte[] result = decryptAesCbc(input, iv, key);
            byte[] backToInput = encryptAesCbc(result, key, iv).Cipher;
            Helpers.PrintUTF8String(unPKCS7(result));

            // How original, the content is the same as for challenge 7 and 6
            return Helpers.QuickCheck(result, 2880, "I'm back and I'm ringin' the bell")
                && Helpers.Equals(backToInput, input);
        }

        private static BlockCipherResult encryptAesCbc(byte[] plain, byte[] key, byte[] iv = null) {
            const int blocksize = 16;
            if (iv == null)
                iv = Helpers.RandomByteArray(16);
            byte[] cipher = new byte[plain.Length];

            byte[] prevBlock = iv;
            for (int i = 0; i < plain.Length; i += blocksize) {
                byte[] block = Helpers.CopyPartOf(plain, i, blocksize);
                block = Helpers.XOR(block, prevBlock);
                block = BlockCipher.EncryptAES(block, key, null, CipherMode.ECB, PaddingMode.None);
                prevBlock = block;
                Array.Copy(block, 0, cipher, i, blocksize);
            }

            return BlockCipher.Result(cipher, iv);
        }

        private static byte[] decryptAesCbc(BlockCipherResult cipherAndIv, byte[] key) {
            return decryptAesCbc(cipherAndIv.Cipher, cipherAndIv.Iv, key);
        }
        private static byte[] decryptAesCbc(byte[] cipher, byte[] iv, byte[] key) {
            const int blocksize = 16;
            byte[] plain = new byte[cipher.Length];

            byte[] prevBlock = iv;
            for (int i = 0; i < cipher.Length; i += blocksize) {
                byte[] block = Helpers.CopyPartOf(cipher, i, blocksize);
                block = BlockCipher.DecryptAES(block, key, null, CipherMode.ECB, PaddingMode.None);
                block = Helpers.XOR(block, prevBlock);
                prevBlock = Helpers.CopyPartOf(cipher, i, blocksize);
                Array.Copy(block, 0, plain, i, blocksize);
            }

            return plain;
        }

        // Implement PKCS#7 padding
        static bool challenge9() {
            // Input:  "YELLOW SUBMARINE"
            // Answer: "YELLOW SUBMARINE\x04\x04\x04\x04"

            byte[] input = Helpers.FromUTF8String("YELLOW SUBMARINE");
            byte blocksize = 20;

            byte[] padded = PKCS7(input, blocksize);
            string result = Helpers.ToUTF8String(padded);
            Console.WriteLine(result);

            return result == "YELLOW SUBMARINE\x04\x04\x04\x04";
        }

        static byte[] PKCS7(byte[] raw, int blocksize = 16) {
            // Add PKCS#7 padding
            return Helpers.ForcePadWith(raw, blocksize, (byte)(blocksize - raw.Length % blocksize));
        }
        static byte[] unPKCS7(byte[] raw) {
            // Remove PKCS#7 padding. Note that the .NET AES doesn't really unpad, it just replaces them with zeroes.
            int paddingLength = getPKCS7(raw);
            return Helpers.CopyPartOf(raw, 0, raw.Length - paddingLength);
        }
        static byte[] zeroPKCS7(byte[] raw) {
            // Remove PKCS#7 padding. This time, overwrite the padding with zeroes, just like the .NET AES.
            int paddingLength = getPKCS7(raw);
            byte[] result = new byte[raw.Length];
            Array.Copy(raw, 0, result, 0, raw.Length - paddingLength);
            return result;
        }
        static int getPKCS7(byte[] raw) {
            // Check whether or not the raw array is a properly PKCS7-padded. Throw when it's not.
            int paddingLength = raw.Last();
            for (int i = 0; i < paddingLength; i++)
                if (raw[raw.Length - i - 1] != paddingLength)
                    return -1;
            return paddingLength;
        }
        static bool checkPKCS7(byte[] raw) {
            return getPKCS7(raw) > 0;
        }

        #endregion

        #region Set 1

        // Run all challenges of set 1
        static bool runSet1() {
            bool result = true;

            Console.WriteLine("Challenge 1:");
            result &= challenge1();
            Console.WriteLine("\nChallenge 2:");
            result &= challenge2();
            Console.WriteLine("\nChallenge 3:");
            result &= challenge3();
            Console.WriteLine("\nChallenge 4:");
            result &= challenge4();
            Console.WriteLine("\nChallenge 5:");
            result &= challenge5();
            Console.WriteLine("\nChallenge 6:");
            result &= challenge6();
            Console.WriteLine("\nChallenge 7:");
            result &= challenge7();
            Console.WriteLine("\nChallenge 8:");
            result &= challenge8();

            return result;
        }

        // Detect ECB mode
        static bool challenge8() {
            // Input:  All hex strings in file Data/8.txt
            // Answer: -

            // Get the lines with the highest number of equal blocks
            // (this does not guarantee anything, it could be chance, but the probability is probably low xD)
            // (I am really assuming that the plaintext has at least some equal blocks)
            int lineNumber = 0;
            ScoreItem[] scoreList = new ScoreItem[5];
            using (StreamReader reader = new StreamReader("Data/8.txt")) {
                string line;
                while ((line = reader.ReadLine()) != null) {
                    // Init
                    lineNumber++;
                    byte[] input = Helpers.FromHexString(line);
                    byte[][] blocks = Helpers.SplitUp(input, 16);

                    // Count the number of equal blocks .
                    ScoreItem current = new ScoreItem(input);
                    current.KeyUsedInt = lineNumber;
                    for (int i = 0; i < blocks.Length - 1; i++)
                        for (int j = i + 1; j < blocks.Length; j++)
                            if (Helpers.Equals(blocks[i], blocks[j]))
                                current.Score--;
                    current.InsertInScoreList(scoreList);
                }
            }

            // Display the best ones
            ScoreItem.DisplayScoreList(scoreList, false);

            return scoreList[0].KeyUsedInt == 133;
        }

        // Decrypt AES-ECB using a key
        static bool challenge7() {
            // Input:  The base64 encoded content of the file Data/7.txt
            //         The key is "YELLOW SUBMARINE"
            // Amswer: -

            byte[] input = Helpers.ReadBase64File("Data/7.txt");
            byte[] key = Helpers.FromUTF8String("YELLOW SUBMARINE");

            byte[] result = BlockCipher.DecryptAES(input, key, null, CipherMode.ECB, PaddingMode.PKCS7);
            Helpers.PrintUTF8String(result);

            return Helpers.QuickCheck(result, 2880, "I'm back and I'm ringin' the bell"); // Padded with 4 zeroes
        }

        // Break a file decrypted with the repeating XOR
        static bool challenge6() {
            // Input:  The base64 encoded content of the file Data/6.txt
            // Answer: -

            // Test hamming distance
            byte[] x = Helpers.FromUTF8String("this is a test");
            byte[] y = Helpers.FromUTF8String("wokka wokka!!!");
            int hammingDistance = Helpers.HammingDistance(x, y);
            Console.WriteLine("Hamming distance: " + hammingDistance.ToString() + "\n");
            if (hammingDistance != 37)
                return false;

            // Read the file
            byte[] input = Helpers.ReadBase64File("Data/6.txt");

            // Find the keysize
            int nrOfSamples = 5;
            ScoreItem[] keysizeList = new ScoreItem[3];
            for (int keysize = 2; keysize < 40; keysize++) {
                ScoreItem current = new ScoreItem(input);
                current.KeyUsedInt = keysize;
                for (int i = 0; i < nrOfSamples * 2; i += 2) {
                    byte[] a = Helpers.CopyPartOf(input, keysize * i, keysize);
                    byte[] b = Helpers.CopyPartOf(input, keysize * (i + 1), keysize);
                    current.Score += Helpers.HammingDistance(a, b);
                }
                current.Score /= nrOfSamples * keysize; // Normalize
                current.InsertInScoreList(keysizeList);
            }
            Console.WriteLine("Keysize and hamming distance:");
            ScoreItem.DisplayScoreList(keysizeList, false);
            Console.WriteLine();

            // Attack the Vigenere cipher, because we are not 100% sure on the keysize, try each of the most likely ones
            foreach (ScoreItem si in keysizeList) {
                int keysize = si.KeyUsedInt;
                byte[] key = attackRepeatingXOR(input, keysize);

                // Print the results for this key
                string possibleMessage = Helpers.ToUTF8String(Helpers.XOR(input, key));
                if (keysize == 29)
                    Console.WriteLine("Keysize: {0}, key: {1}, message: {2}", keysize, Helpers.ToHexString(key, true), possibleMessage);
            }

            // Return true when one of the tried keysizes is 29 (0x1D)
            return keysizeList.Any(t => t.KeyUsedInt == 29);
        }

        static byte[] attackRepeatingXOR(byte[] input, int keysize, byte[] keySoFar = null) {
            // Analyze all the blocks that have the same key - attacking each transposed block will give us one byte of the key (using the single XOR attack)
            byte[] key = new byte[keysize];
            if (keySoFar != null)
                Array.Copy(keySoFar, key, keySoFar.Length);

            byte[][] transposed = Helpers.Transpose(Helpers.SplitUp(input, keysize));
            for (int j = keySoFar.Length; j < transposed.Length; j++)
                key[j] = attackSingleXOR(transposed[j]);

            return key;
        }

        // Encrypt a message using a repeating XOR
        static bool challenge5() {
            // Input:  Burning 'em, if you ain't quick and nimble
            //         I go crazy when I hear a cymbal
            //         Key: ICE
            // Answer: 0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272
            //         a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f

            string message = "Burning 'em, if you ain't quick and nimble" + "\n" + "I go crazy when I hear a cymbal"; // Using a unix newline!
            byte[] key = Helpers.FromUTF8String("ICE");
            byte[] plain = Helpers.FromUTF8String(message);

            string result = Helpers.ToHexString(Helpers.XOR(plain, key));
            Console.WriteLine(result);

            return result == "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272"
                + "a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";
        }

        // Detect (and break) the message encrypted with a single XOR
        static bool challenge4() {
            // Input:  All hex strings in file Data/4.txt
            // Answer: -

            // Inits
            ScoreItem[] scoreList = new ScoreItem[10];

            using (StreamReader reader = new StreamReader("Data/4.txt")) {
                string line;
                while ((line = reader.ReadLine()) != null) {
                    byte[] input = Helpers.FromHexString(line);

                    // Attack
                    attackSingleXOR(input, scoreList);
                }
            }

            // Display the best plain texts
            ScoreItem.DisplayScoreList(scoreList);

            return scoreList[0].Utf8String == "Now that the party is jumping\n";
        }

        // Crack the message encrypted with a single XOR
        static bool challenge3() {
            // Input:  1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736
            // Answer: -
            bool test = true;

            // Inits
            byte[] input = Helpers.FromHexString("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736");
            ScoreItem[] scoreList = new ScoreItem[5];

            // Attack
            attackSingleXOR(input, scoreList);

            // Display the best plain texts
            ScoreItem.DisplayScoreList(scoreList);

            return scoreList[0].Utf8String == "Cooking MC's like a pound of bacon";
        }

        static byte attackSingleXOR(byte[] input, ScoreItem[] scoreList) {
            // Calculate XOR with all possible keys [0, 256) and insert it in the score list
            for (int k = 0; k < 256; k++) {
                byte[] key = new byte[1] { (byte)k };
                ScoreItem.InsertFrequencyAnalysis(Helpers.XOR(input, key), key, scoreList);
            }
            return scoreList[0].KeyUsed[0];
        }
        static byte attackSingleXOR(byte[] input) {
            return attackSingleXOR(input, new ScoreItem[1]);
        }

        // XOR two byte arrays
        static bool challenge2() {
            // Input:  1c0111001f010100061a024b53535009181c
            //         686974207468652062756c6c277320657965
            // Answer: 746865206b696420646f6e277420706c6179

            byte[] a = Helpers.FromHexString("1c0111001f010100061a024b53535009181c");
            byte[] b = Helpers.FromHexString("686974207468652062756c6c277320657965");

            string result = Helpers.ToHexString(Helpers.XOR(a, b));
            Console.WriteLine(result);

            // Easter eggs - b: "hit the bull's eye", a^b: "the kid don't play"
            return result == "746865206b696420646f6e277420706c6179";
        }

        // Read a hex string and output it as base64
        static bool challenge1() {
            // Input:  49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d
            // Answer: SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t

            // Easter egg - Input: "I'm killing your brain like a poisenous mushroom"
            byte[] input = Helpers.FromHexString("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d");
            string result = Convert.ToBase64String(input);
            Console.WriteLine(result);

            return result == "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";
        }

        #endregion
    }
}
