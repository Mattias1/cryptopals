using System;
using System.Linq;
using System.Security.Cryptography;

namespace CryptoPals
{
    class Set2 : Set
    {
        // Run all challenges of set 2
        public static bool runSet2() {
            return runSet(9, challenge9, challenge10, challenge11, challenge12, challenge13, challenge14, challenge15, challenge16);
        }

        // Modify a CBC encrypted cookie (bitflipping)
        public static bool challenge16() {
            // The goal again is to modify the (AES-123 CBC encrypted) cookie and slip an admin=true inside
            // Input:   Number of bytes in the cookie string before our content: 8+1+13+1+8+1 = 32 bytes prepending data (exactly 2 blocks, easy for us)
            //          Number of bytes for the "&admin=true" string: 1+5+1+4 = 11 bytes

            // Plan: insert some random userdata (2 blocks) and then insert the &admin=true, but without the = and & signs.
            // Then afterwards we modify the ciphertext of the first block of 'userdata' so that the = and & signs will be XOR-ed in.
            byte[] userdata = ByteArrayHelpers.Concatenate(new byte[32], ConversionHelpers.FromUTF8String("_admin_true"));
            byte[] cipher = encryptionOracle16(userdata);

            byte[] xors = new byte[cipher.Length];
            byte _ = ConversionHelpers.FromUTF8Char('_');
            byte and = ConversionHelpers.FromUTF8Char('&');
            byte eq = ConversionHelpers.FromUTF8Char('=');
            xors[49] = (byte)(_ ^ and);
            xors[55] = (byte)(_ ^ eq);

            cipher = ByteArrayHelpers.XOR(cipher, xors);

            bool hackSucceeded = decryptionOracle16(cipher);

            Console.WriteLine(hackSucceeded ? "Yummy, admin rights" : "Awww, no admin");
            return hackSucceeded;
        }

        static byte[] encryptionOracle16(byte[] input) {
            // Emulate a function at the server to cook some userData like a pound of bacon
            const int blocksize = 16;

            // Generate a random (so unknown) key and use it throughout the rest of the program
            if (fixedKey == null)
                fixedKey = RandomHelpers.RandomByteArray(blocksize);

            // Generate cookie and encrypt it
            string userData = ConversionHelpers.ToUTF8String(input);
            KeyValuePairs cookie = KeyValuePairs.CookingUserdata(userData);
            string url = cookie.ToUrl();
            byte[] cipher = ConversionHelpers.FromUTF8String(url);
            return BlockCipher.EncryptAES(cipher, fixedKey, new byte[blocksize], CipherMode.CBC, PaddingMode.PKCS7);
        }

        static bool decryptionOracle16(byte[] cipher) {
            // Check the cookie for admin access
            const int blocksize = 16;

            // Decrypt the cookie
            byte[] original = BlockCipher.DecryptAES(cipher, fixedKey, new byte[blocksize], CipherMode.CBC, PaddingMode.None);
            byte[] plain = unPKCS7(original);

            // Check for admin rights
            string url = ConversionHelpers.ToUTF8String(plain);
            int l_plain = plain.Length;
            int l_url = url.Length;
            KeyValuePairs cookie = KeyValuePairs.FromURL(url);
            return cookie["admin"] == "true";
        }

        // Remove PKCS#7 padding, with exception if it fails
        public static bool challenge15() {
            // Input:  "ICE ICE BABY\x04\x04\x04\x04", "ICE ICE BABY\x05\x05\x05\x05", "ICE ICE BABY\x01\x02\x03\x04"
            // Answer: "ICE ICE BABY", exception, exception
            bool exception1 = false, exception2 = false;

            string result = ConversionHelpers.ToUTF8String(unPKCS7(ConversionHelpers.FromUTF8String("ICE ICE BABY\x04\x04\x04\x04")));
            Console.WriteLine(result);

            if (!checkPKCS7(ConversionHelpers.FromUTF8String("ICE ICE BABY\x05\x05\x05\x05"))) {
                exception1 = true;
                Console.WriteLine("Bad padding");
            }

            if (!checkPKCS7(ConversionHelpers.FromUTF8String("ICE ICE BABY\x01\x02\x03\x04"))) ;
            {
                exception2 = true;
                Console.WriteLine("Bad padding");
            }

            return result == "ICE ICE BABY" && exception1 && exception2;
        }

        // Byte at a time ECB decryption (hard)
        public static bool challenge14() {
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
                byte[][] cipherBlocks = ByteArrayHelpers.SplitUp(cipher, blocksize);

                bool foundPrefixLength = false;
                for (int j = 0; j < cipherBlocks.Length - equalBlocks; j++) {
                    foundPrefixLength = true;
                    for (int k = equalBlocks - 1; k >= 1; k--) {
                        if (!MiscHelpers.Equals(cipherBlocks[j], cipherBlocks[j + k])) {
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
                    lookupTable[b] = ByteArrayHelpers.CopyPartOf(cipher, totalPrefixLength, blocksize);  // And there we have all possible encryptions if the block is being feeded to the oracle such that the unknown byte is at the back
                }
                // Lookup the value of the byte to crack
                int offset = hackPosition / blocksize * blocksize;
                input = new byte[inversePrefixLength + blocksize - hackPosition + offset - 1];
                cipher = ByteArrayHelpers.CopyPartOf(encryptionOracle14(input), totalPrefixLength + offset, blocksize);
                for (int b = 0; b < 256; b++)
                    if (MiscHelpers.Equals(lookupTable[b], cipher)) {
                        result[hackPosition] = (byte)b;
                        break;
                    }
            }

            // The decrypted message
            ConversionHelpers.PrintUTF8String(result);

            return MiscHelpers.QuickCheck(result, 138, "Rollin' in my 5.0");
        }

        static byte[] encryptionOracle14(byte[] input) {
            // This function takes an input and encrypts it with a fixed unknown key (fixedKey)
            const int blocksize = 16;

            // Generate a random (so unknown) key and use it throughout the rest of the program
            if (fixedKey == null) {
                fixedKey = RandomHelpers.RandomByteArray(blocksize);
                fixedBytes = RandomHelpers.RandomByteArray(RandomHelpers.Random.Next(5, 55));
            }

            // The plaintext to encrypt will be [random_prefix + input + secret message] (the secret message that we want to decrypt)
            byte[] secretMessage = Convert.FromBase64String(
                "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg"
                + "aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq"
                + "dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg"
                + "YnkK");
            byte[] plain = ByteArrayHelpers.Concatenate(fixedBytes, input, secretMessage);

            // Encrypt and return
            return BlockCipher.EncryptAES(plain, fixedKey, null, CipherMode.ECB, PaddingMode.PKCS7);
        }

        // ECB cut-and-paste
        public static bool challenge13() {
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
            const int blocksize = 16;
            byte[] before = ConversionHelpers.FromUTF8String("AAAAAAAAAA");
            byte[] adminWord = PKCS7(ConversionHelpers.FromUTF8String("admin"), blocksize);
            byte[] after = ConversionHelpers.FromUTF8String("@gmail.com");
            byte[] input = ByteArrayHelpers.Concatenate(before, adminWord, after);
            byte[] cipher = encryptionOracle13(input);
            byte[] encryptedAdminWord = ByteArrayHelpers.CopyPartOf(cipher, blocksize, blocksize);

            // Second try
            input = ConversionHelpers.FromUTF8String("AAAA@gmail.com");
            cipher = encryptionOracle13(input);
            before = ByteArrayHelpers.CopyPartOf(cipher, 0, 2 * blocksize);
            byte[] encryptedResult = ByteArrayHelpers.Concatenate(before, encryptedAdminWord);

            // Lets 'send' our hacked cookie back to the server and print here what the server would see
            byte[] result = BlockCipher.DecryptAES(encryptedResult, fixedKey, null, CipherMode.ECB, PaddingMode.PKCS7);
            ConversionHelpers.PrintUTF8String(result);

            return MiscHelpers.QuickCheck(result, 3 * blocksize, "email=AAAA@gmail.com&uid=1&role=admin");
        }

        static byte[] encryptionOracle13(byte[] email) {
            // Emulate a function at the server to generate a valid encrypted cookie
            const int blocksize = 16;

            // Generate a random (so unknown) key and use it throughout the rest of the program
            if (fixedKey == null) {
                fixedKey = RandomHelpers.RandomByteArray(blocksize);
            }

            // Generate cookie and encrypt it
            string emailAddress = ConversionHelpers.ToUTF8String(email);
            KeyValuePairs cookie = KeyValuePairs.ProfileFor(emailAddress);
            string url = cookie.ToUrl();
            return BlockCipher.EncryptAES(ConversionHelpers.FromUTF8String(url), fixedKey, null, CipherMode.ECB, PaddingMode.PKCS7);
        }

        // Byte at a time ECB decription (simple) - Break AES in ECB mode o_O
        public static bool challenge12() {
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
                    lookupTable[b] = ByteArrayHelpers.CopyPartOf(cipher, 0, blocksize);  // And there we have all possible encryptions if the block is being feeded to the oracle such that the unknown byte is at the back
                }
                // Lookup the value of the byte to crack
                int offset = hackPosition / blocksize * blocksize;
                input = new byte[blocksize - hackPosition + offset - 1];
                cipher = ByteArrayHelpers.CopyPartOf(encryptionOracle12(input), offset, blocksize);
                for (int b = 0; b < 256; b++)
                    if (MiscHelpers.Equals(lookupTable[b], cipher)) {
                        result[hackPosition] = (byte)b;
                        break;
                    }
            }

            // The decrypted message
            ConversionHelpers.PrintUTF8String(result);

            return MiscHelpers.QuickCheck(result, 138, "Rollin' in my 5.0");
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
            const int blocksize = 16;

            // Generate a random (so unknown) key and use it throughout the rest of the program
            if (fixedKey == null)
                fixedKey = RandomHelpers.RandomByteArray(blocksize);

            // The plaintext to encrypt will be [input + secret message] (the secret message that we want to decrypt)
            byte[] secretMessage = Convert.FromBase64String(
                "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg"
                + "aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq"
                + "dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg"
                + "YnkK");
            byte[] plain = ByteArrayHelpers.Concatenate(input, secretMessage);

            // Encrypt and return
            return BlockCipher.EncryptAES(plain, fixedKey, null, CipherMode.ECB, PaddingMode.PKCS7);
        }

        // An ECB/CBC detection oracle
        public static bool challenge11() {
            // The goal is to write something that given a black box, that it detects whether it encrypts with ECB or CBC
            // Input:  -

            Console.WriteLine("Whether or not the oracle used ECB mode or not (CBC mode)");
            for (int i = 0; i < 10; i++)
                Console.WriteLine("  ECB detected: " + oracleUsesECB(randomECB_CBCEncryptionOracle).ToString());

            return true;
        }

        static bool oracleUsesECB(Func<byte[], byte[]> oracleFunction) {
            // Detect whether or not the function encrypted using ECB mode
            const int blocksize = 16;
            int blocks = 6;

            byte[] input = new byte[blocks * blocksize]; // input some blocks with only zeroes - at least 5 of them should give equal blocks after encryption with ECB
            byte[][] cipherBlocks = ByteArrayHelpers.SplitUp(oracleFunction(input), blocksize);

            int equalBlocks = 1;
            for (int i = 0; i < cipherBlocks.Length - 1; i++)
                if (MiscHelpers.Equals(cipherBlocks[i], cipherBlocks[i + 1]))
                    equalBlocks++;

            return equalBlocks >= blocks - 1;
        }

        static byte[] randomECB_CBCEncryptionOracle(byte[] input) {
            // This function takes an input and encrypts it randomly with ECB or CBC. It also adds random bytes before and after the input array.

            // Initialize
            byte[] key = RandomHelpers.RandomByteArray(16);
            byte[] before = RandomHelpers.RandomByteArray(RandomHelpers.Random.Next(5, 11));
            byte[] after = RandomHelpers.RandomByteArray(RandomHelpers.Random.Next(5, 11));
            byte[] iv = null;

            // Create the result array with the original and generated input
            byte[] result = ByteArrayHelpers.Concatenate(before, key, after);

            // Encrypt the result array
            if (RandomHelpers.Random.Next(2) == 0) {
                // ECB
                Console.WriteLine("The encryption oracle secretly used ECB mode... ");
                result = BlockCipher.EncryptAES(result, key, null, CipherMode.ECB, PaddingMode.PKCS7);
            }
            else {
                // CBC
                Console.WriteLine("The encryption oracle secretly used CBC mode... ");
                iv = RandomHelpers.RandomByteArray(key.Length);
                result = BlockCipher.EncryptAES(result, key, iv, CipherMode.CBC, PaddingMode.PKCS7);
            }
            return result;
        }

        // Implement CBC mode of AES
        public static bool challenge10() {
            // Input:  The base64 encoded content of file Data/10.txt
            //         The key is: "YELLOW SUBMARINE"
            //         The IV consists of all ASCII 0 charachters ("\x00\x00\x00...")

            byte[] input = ConversionHelpers.ReadBase64File("Data/10.txt");
            byte[] key = ConversionHelpers.FromUTF8String("YELLOW SUBMARINE");
            byte[] iv = new byte[key.Length];

            byte[] result = decryptAesCbc(input, iv, key);
            byte[] backToInput = encryptAesCbc(result, key, iv).Cipher;
            ConversionHelpers.PrintUTF8String(unPKCS7(result));

            // How original, the content is the same as for challenge 7 and 6
            return MiscHelpers.QuickCheck(result, 2880, "I'm back and I'm ringin' the bell")
                && MiscHelpers.Equals(backToInput, input);
        }

        private static BlockCipherResult encryptAesCbc(byte[] plain, byte[] key, byte[] iv = null) {
            const int blocksize = 16;
            if (iv == null)
                iv = RandomHelpers.RandomByteArray(16);
            byte[] cipher = new byte[plain.Length];

            byte[] prevBlock = iv;
            for (int i = 0; i < plain.Length; i += blocksize) {
                byte[] block = ByteArrayHelpers.CopyPartOf(plain, i, blocksize);
                block = ByteArrayHelpers.XOR(block, prevBlock);
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
                byte[] block = ByteArrayHelpers.CopyPartOf(cipher, i, blocksize);
                block = BlockCipher.DecryptAES(block, key, null, CipherMode.ECB, PaddingMode.None);
                block = ByteArrayHelpers.XOR(block, prevBlock);
                prevBlock = ByteArrayHelpers.CopyPartOf(cipher, i, blocksize);
                Array.Copy(block, 0, plain, i, blocksize);
            }

            return plain;
        }

        // Implement PKCS#7 padding
        public static bool challenge9() {
            // Input:  "YELLOW SUBMARINE"
            // Answer: "YELLOW SUBMARINE\x04\x04\x04\x04"

            byte[] input = ConversionHelpers.FromUTF8String("YELLOW SUBMARINE");
            byte blocksize = 20;

            byte[] padded = PKCS7(input, blocksize);
            string result = ConversionHelpers.ToUTF8String(padded);
            Console.WriteLine(result);

            return result == "YELLOW SUBMARINE\x04\x04\x04\x04";
        }

        public static byte[] PKCS7(byte[] raw, int blocksize = 16) {
            // Add PKCS#7 padding
            return ByteArrayHelpers.ForcePadWith(raw, blocksize, (byte)(blocksize - raw.Length % blocksize));
        }
        public static byte[] unPKCS7(byte[] raw) {
            // Remove PKCS#7 padding. Note that the .NET AES doesn't really unpad, it just replaces them with zeroes.
            int paddingLength = getPKCS7(raw);
            return ByteArrayHelpers.CopyPartOf(raw, 0, raw.Length - paddingLength);
        }
        public static byte[] zeroPKCS7(byte[] raw) {
            // Remove PKCS#7 padding. This time, overwrite the padding with zeroes, just like the .NET AES.
            int paddingLength = getPKCS7(raw);
            byte[] result = new byte[raw.Length];
            Array.Copy(raw, 0, result, 0, raw.Length - paddingLength);
            return result;
        }
        public static int getPKCS7(byte[] raw) {
            // Check whether or not the raw array is a properly PKCS7-padded. Return -1 when not valid.
            int paddingLength = raw.Last();
            for (int i = 0; i < paddingLength; i++)
                if (raw[raw.Length - i - 1] != paddingLength)
                    return -1;
            return paddingLength;
        }
        public static bool checkPKCS7(byte[] raw) {
            return getPKCS7(raw) > 0;
        }
    }
}
