using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;

namespace CryptoPals
{
    class Program
    {
        static byte[] fixedKey, fixedBytes;

        static void Main(string[] args) {
            Console.WriteLine("\n Crypto pals challenges output:");
            Console.WriteLine("--------------------------------\n");

            bool result = challenge17();

            Console.WriteLine("\n--------------------------------");
            Console.WriteLine(result ? " SUCCESS!" : " FAIL!");
            Console.ReadLine();
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

        // Modify a CBC encrypted cookie
        static bool challenge16() {
            // The goal again is to modify the (AES-123 CBC encrypted) cookie and slip an admin=true inside
            // Input:   Number of bytes in the cookie string before our content: 8+1+13+1+8+1 = 32 bytes prepending data (exactly 2 blocks, easy for us)
            //          Number of bytes for the "&admin=true" string: 1+5+1+4 = 11 bytes

            // Plan: insert some random userdata (1 block) and then insert the &admin=true, but without the = and & signs.
            // Then afterwards we modify the ciphertext of the first block of 'userdata' so that the = and & signs will be XOR-ed in.
            string userdata = "---4---8---4---8" + "_admin_true";
            byte[] cipher = encryptionOracle16(Helpers.FromUTF8String(userdata));

            byte[] xors = new byte[cipher.Length];
            byte _ = Helpers.FromUTF8String("_")[0];
            byte and = Helpers.FromUTF8String("&")[0];
            byte eq = Helpers.FromUTF8String("=")[0];
            xors[33] = (byte)(_ ^ and);
            xors[39] = (byte)(_ ^ eq);

            cipher = Helpers.XOR(cipher, xors);

            return decryptionOracle16(cipher);
        }

        static byte[] encryptionOracle16(byte[] input) {
            // Emulate a function at the server to cook some userData like a pound of bacon
            int blocksize = 16;

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
            int blocksize = 16;

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

            // byte[] result = BlockCipher.Decrypt<AesManaged>(input, key, iv, CipherMode.CBC); // HAX! CHEAT!
            int blocksize = 16;
            byte[] result = new byte[input.Length];
            byte[] block = iv, prevBlock = iv;
            for (int i = 0; i < input.Length; i += blocksize) {
                block = Helpers.CopyPartOf(input, i, blocksize);
                block = BlockCipher.DecryptAES(block, key, null, CipherMode.ECB, PaddingMode.None);
                block = Helpers.XOR(block, prevBlock);
                prevBlock = Helpers.CopyPartOf(input, i, blocksize);
                Array.Copy(block, 0, result, i, blocksize);
            }
            result = zeroPKCS7(result);
            Helpers.PrintUTF8String(result);

            // How original, the content is the same as for challenge 7 and 6
            return Helpers.QuickCheck(result, 2880, "I'm back and I'm ringin' the bell");
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
        static byte[] unPKCS7(byte[] raw, int blocksize = 16) {
            // Remove PKCS#7 padding. Note that the .NET AES doesn't really unpad, it just replaces them with zeroes.
            int paddingLength = getPKCS7(raw);
            return Helpers.CopyPartOf(raw, 0, raw.Length - paddingLength);
        }
        static byte[] zeroPKCS7(byte[] raw, int blocksize = 16) {
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
            for (int i = 0; i < keysizeList.Length; i++) {
                int keysize = keysizeList[i].KeyUsedInt;

                // Analyze all the blocks that have the same key - attacking each transposed block will give us one byte of the key (using the single XOR attack)
                byte[] key = new byte[keysize];
                byte[][] transposed = Helpers.Transpose(Helpers.SplitUp(input, keysize));
                for (int j = 0; j < transposed.Length; j++)
                    key[j] = attackSingleXOR(transposed[j]);

                // Print the results for this key
                string possibleMessage = Helpers.ToUTF8String(Helpers.XOR(input, key));
                if (keysize == 29)
                    Console.WriteLine("Keysize: " + keysize.ToString() + ", key: " + Helpers.ToHexString(key, true) + ", message: " + possibleMessage);
            }

            // Return true when one of the tried keysizes is 29 (0x1D)
            for (int i = 0; i < keysizeList.Length; i++)
                if (keysizeList[i].KeyUsedInt == 29)
                    return true;
            return false;
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
            byte[] key = new byte[1];
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

            return scoreList[0].UTF8String == "Now that the party is jumping\n";
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

            return scoreList[0].UTF8String == "Cooking MC's like a pound of bacon";
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
