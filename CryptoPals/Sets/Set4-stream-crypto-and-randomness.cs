﻿using System;
using System.Linq;
using System.Security.Cryptography;

namespace CryptoPals
{
    class Set4
    {
        static byte[] fixedKey, fixedBytes;

        // Break a MD4-keyed MAC using length extension
        public static bool challenge30() {
            assertMd4();

            // Get the original message and hash
            byte[] message;
            byte[] hash = macOracle30(out message);
            uint[] lengthExtensionInitHash = ByteArrayHelpers.SplitUp(hash, 4).Select(ConversionHelpers.ToUInt).ToArray();

            if (!checkMessageMac30(message, hash)) {
                Console.WriteLine("Error, initial mac is not correct.");
                return false;
            }
            if (!MiscHelpers.Equals(ConversionHelpers.ToLittleEndianByteArray(lengthExtensionInitHash), hash)) {
                Console.WriteLine("Error parsing the initial hash.");
                return false;
            }

            bool hackSucceeded = false;
            for (int keyLength = 0; keyLength < 100; keyLength++) {
                // Forge the tampered message
                byte[] extraMessage = ConversionHelpers.FromUTF8String("&admin=true");
                byte[] messageWith0Key = ByteArrayHelpers.Concatenate(new byte[keyLength], message); // The key is necessary for the MdPadding
                byte[] leMessageWith0Key = ByteArrayHelpers.Concatenate(Md4.MdPadding(messageWith0Key), extraMessage);
                byte[] lengthExtensionMessage = ByteArrayHelpers.CopyPartOf(leMessageWith0Key, keyLength, leMessageWith0Key.Length - keyLength);

                var newCookie = KeyValuePairs.FromURL(ConversionHelpers.ToUTF8String(lengthExtensionMessage));
                if (newCookie["admin"] != "true") {
                    Console.WriteLine("Error, new cookie is not gonna give us admin rights.");
                    return false;
                }

                // Forge the hash
                int originalHashLengthGuess = Md4.MdPaddingLength(messageWith0Key);
                byte[] newHash = Md4.HashLengthExtension(extraMessage, originalHashLengthGuess, lengthExtensionInitHash);

                hackSucceeded = checkMessageMac30(lengthExtensionMessage, newHash);
                if (hackSucceeded)
                    break;
            }
            Console.WriteLine(hackSucceeded ? "I AM ADMIN" : "Hack failed.");

            return hackSucceeded;
        }

        private static bool assertMd4() {
            // Make sure the Md4 hash is implemented correctly
            foreach (var knownHash in Md4.KnownHashes) {
                string hash = Md4.Hash(knownHash.Key);
                if (hash != knownHash.Value) {
                    Console.WriteLine($"In: '{knownHash.Key}'");
                    Console.WriteLine($"Berekende hash:  {hash}");
                    Console.WriteLine($"Verwachtte hash: {knownHash.Value}\n");

                    throw new Exception("MD4 error");
                }
            }
            return true;
        }

        static byte[] macOracle30(out byte[] message) {
            fixedKey = RandomHelpers.RandomByteArray(16);

            var cookie = KeyValuePairs.CookingUserdata("foo");
            message = ConversionHelpers.FromUTF8String(cookie.ToUrl());
            byte[] hash = Md4.Mac(fixedKey, message);

            return hash;
        }

        static bool checkMessageMac30(byte[] message, byte[] mac) {
            byte[] hash = Md4.Mac(fixedKey, message);
            return MiscHelpers.Equals(hash, mac);
        }

        // Break a SHA-1 keyed MAC using length extension
        public static bool challenge29() {
            // Get the original message and hash
            byte[] message;
            byte[] hash = macOracle29(out message);
            uint[] lengthExtensionInitHash = ByteArrayHelpers.SplitUp(hash, 4).Select(ConversionHelpers.BigEndianToUint).ToArray();

            if (!checkMessageMac29(message, hash)) {
                Console.WriteLine("Error, initial mac is not correct.");
                return false;
            }
            if (!MiscHelpers.Equals(ConversionHelpers.ToBigEndianByteArray(lengthExtensionInitHash), hash)) {
                Console.WriteLine("Error parsing the initial hash.");
                return false;
            }

            bool hackSucceeded = false;
            for (int keyLength = 0; keyLength < 100; keyLength++) {
                // Forge the tampered message
                byte[] extraMessage = ConversionHelpers.FromUTF8String("&admin=true");
                byte[] messageWith0Key = ByteArrayHelpers.Concatenate(new byte[keyLength], message); // The key is necessary for the MdPadding
                byte[] leMessageWith0Key = ByteArrayHelpers.Concatenate(Sha1.MdPadding(messageWith0Key), extraMessage);
                byte[] lengthExtensionMessage = ByteArrayHelpers.CopyPartOf(leMessageWith0Key, keyLength, leMessageWith0Key.Length - keyLength);

                var newCookie = KeyValuePairs.FromURL(ConversionHelpers.ToUTF8String(lengthExtensionMessage));
                if (newCookie["admin"] != "true") {
                    Console.WriteLine("Error, new cookie is not gonna give us admin rights.");
                    return false;
                }

                // Forge the hash
                int originalHashLengthGuess = Sha1.MdPaddingLength(messageWith0Key);
                byte[] newHash = Sha1.HashLengthExtension(extraMessage, originalHashLengthGuess, lengthExtensionInitHash);

                hackSucceeded = checkMessageMac29(lengthExtensionMessage, newHash);
                if (hackSucceeded)
                    break;
            }
            Console.WriteLine(hackSucceeded ? "I AM ADMIN" : "Hack failed.");

            return hackSucceeded;
        }

        static byte[] macOracle29(out byte[] message) {
            fixedKey = RandomHelpers.RandomByteArray(16);

            var cookie = KeyValuePairs.CookingUserdata("foo");
            message = ConversionHelpers.FromUTF8String(cookie.ToUrl());
            byte[] hash = Sha1.Mac(fixedKey, message);

            return hash;
        }

        static bool checkMessageMac29(byte[] message, byte[] mac) {
            byte[] hash = Sha1.Mac(fixedKey, message);
            return MiscHelpers.Equals(hash, mac);
        }

        // Implement SHA-1 MAC
        public static bool challenge28() {
            // Make sure the sha1 hash is implemented correctly
            foreach (var knownHash in Sha1.KnownHashes) {
                string hash = Sha1.Hash(knownHash.Key);
                if (hash != knownHash.Value) {
                    Console.WriteLine($"In: '{knownHash.Key}'");
                    Console.WriteLine($"Berekende hash:  {hash}");
                    Console.WriteLine($"Verwachtte hash: {knownHash.Value}\n");
                    return false;
                }
            }

            // Test our SHA-1 keyed MAC
            byte[] key = RandomHelpers.RandomByteArray(16);
            byte[] mac = Sha1.Mac(key, ConversionHelpers.FromUTF8String("Hi there"));
            ConversionHelpers.PrintHexString("MAC: ", mac);

            byte[] macTempered = Sha1.Mac(key, ConversionHelpers.FromUTF8String("Hi therE"));
            if (MiscHelpers.Equals(macTempered, mac)) {
                Console.WriteLine("Tempered message gives the same mac!");
                return false;
            }

            byte[] newMac = Sha1.Hash(ConversionHelpers.FromUTF8String("Hi there"));
            if (MiscHelpers.Equals(newMac, mac)) {
                Console.WriteLine("New mac is the same as the original mac!");
                return false;
            }

            return true;
        }

        // Break CBC key where IV = Key
        public static bool challenge27() {
            const int blocksize = 16;

            byte[] input = RandomHelpers.RandomByteArray(60); // long enough
            byte[] cipher = encryptionOracle27(input);

            byte[] firstBlock = ByteArrayHelpers.CopyPartOf(cipher, 0, blocksize);
            Array.Copy(new byte[blocksize], 0, cipher, blocksize, blocksize);
            Array.Copy(firstBlock, 0, cipher, 2 * blocksize, blocksize);

            try {
                decryptionOracle27(cipher);
            }
            catch (Exception e) {
                byte[] decryption = ConversionHelpers.FromHexString(e.Message);
                firstBlock = ByteArrayHelpers.CopyPartOf(decryption, 0, blocksize);
                byte[] thirdBlock = ByteArrayHelpers.CopyPartOf(decryption, 2 * blocksize, blocksize);

                byte[] key = ByteArrayHelpers.XOR(firstBlock, thirdBlock);
                ConversionHelpers.PrintHexString("Key: ", key);
                return MiscHelpers.Equals(key, fixedKey);
            }

            Console.WriteLine("No high ascii values after modifying the cipher o_O");
            return false;
        }

        static byte[] encryptionOracle27(byte[] input) {
            // CBC encrypt with IV = key
            const int blocksize = 16;
            if (fixedKey == null)
                fixedKey = RandomHelpers.RandomByteArray(blocksize);

            string userData = ConversionHelpers.ToUTF8String(input);
            KeyValuePairs cookie = KeyValuePairs.CookingUserdata(userData);
            string url = cookie.ToUrl();
            return BlockCipher.EncryptAES(ConversionHelpers.FromUTF8String(url), fixedKey, fixedKey, CipherMode.CBC, PaddingMode.PKCS7);
        }

        static bool decryptionOracle27(byte[] cipher) {
            byte[] original = BlockCipher.DecryptAES(cipher, fixedKey, fixedKey, CipherMode.CBC, PaddingMode.None);
            byte[] plain = Set2.unPKCS7(original);

            // If the plain contains high ascii values, return exception with the (decrypted) plaintext
            if (plain.Any(b => b > (int)'z' + 20))
                throw new Exception(ConversionHelpers.ToHexString(plain));

            KeyValuePairs cookie = KeyValuePairs.FromURL(ConversionHelpers.ToUTF8String(plain));
            return cookie["admin"] == "true";
        }

        // Modify a CTR encrypted cookie (bitflipping)
        public static bool challenge26() {
            string userdata = "---4---8---4---8" + "_admin_true";
            BlockCipherResult cipherAndNonce = encryptionOracle26(ConversionHelpers.FromUTF8String(userdata));
            byte[] cipher = cipherAndNonce.Cipher;

            // index of first '_' char is: 8 + 1 + 14 + 1 + 8 + 1 + 16 = 49
            byte[] xors = new byte[cipher.Length];
            byte _ = ConversionHelpers.FromUTF8Char('_');
            byte and = ConversionHelpers.FromUTF8Char('&');
            byte eq = ConversionHelpers.FromUTF8Char('=');
            xors[49] = (byte)(_ ^ and);
            xors[49 + 6] = (byte)(_ ^ eq);

            cipher = ByteArrayHelpers.XOR(cipher, xors);
            cipherAndNonce.Cipher = cipher;

            return decryptionOracle26(cipherAndNonce);
        }

        static BlockCipherResult encryptionOracle26(byte[] input) {
            const int blocksize = 16;

            byte[] nonce = RandomHelpers.RandomByteArray(8);
            if (fixedKey == null)
                fixedKey = RandomHelpers.RandomByteArray(blocksize);

            string userData = ConversionHelpers.ToUTF8String(input);
            var cookie = KeyValuePairs.CookingUserdata(userData);
            byte[] urlBytes = ConversionHelpers.FromUTF8String(cookie.ToUrl());

            return BlockCipher.Result(Set3.encryptOrDecryptAesCtr(urlBytes, fixedKey, nonce), nonce);
        }

        static bool decryptionOracle26(BlockCipherResult cipherAndNonce) {
            byte[] plain = Set3.encryptOrDecryptAesCtr(cipherAndNonce, fixedKey);

            var cookie = KeyValuePairs.FromURL(ConversionHelpers.ToUTF8String(plain));
            return cookie["admin"] == "true";
        }

        // Break 'random access read/write' AES CTR
        public static bool challenge25() {
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

            ConversionHelpers.PrintUTF8String(plain);

            return MiscHelpers.QuickCheck(plain, 2880, "I'm back and I'm ringin' the bell");
        }

        static BlockCipherResult encryptionOracle25() {
            byte[] input = ConversionHelpers.ReadBase64File("Data/25.txt"); // Encrypted input from challenge 7
            byte[] key = ConversionHelpers.FromUTF8String("YELLOW SUBMARINE");
            input = BlockCipher.DecryptAES(input, key, null, CipherMode.ECB, PaddingMode.PKCS7);

            byte[] nonce = RandomHelpers.RandomByteArray(8);
            if (fixedKey == null)
                fixedKey = RandomHelpers.RandomByteArray(16);

            byte[] cipher = Set3.encryptOrDecryptAesCtr(input, fixedKey, nonce);
            return BlockCipher.Result(cipher, nonce);
        }

        static byte[] editOracle(BlockCipherResult cipherAndNonce, int offset, byte replacement) {
            // Optimized version for changing 1 byte only
            const int blocksize = 16;
            const int halfBlocksize = blocksize / 2;

            // Generate the keystream for the block the new plain byte is in
            byte[] result = ByteArrayHelpers.Copy(cipherAndNonce.Cipher);
            int counter = offset / blocksize;
            int blockStart = counter * blocksize;
            byte[] block = ByteArrayHelpers.CopyPartOf(cipherAndNonce.Cipher, blockStart, blocksize);

            byte[] nonceAndCounter = new byte[blocksize];
            Array.Copy(cipherAndNonce.Iv, nonceAndCounter, halfBlocksize);
            Array.Copy(ConversionHelpers.ToLittleEndian((ulong)counter), 0, nonceAndCounter, halfBlocksize, halfBlocksize);

            byte[] keystream = BlockCipher.EncryptAES(nonceAndCounter, fixedKey, null, CipherMode.ECB, PaddingMode.None);

            // Change the old plain byte
            block = ByteArrayHelpers.XOR(block, keystream);
            block[offset - blockStart] = replacement;
            block = ByteArrayHelpers.XOR(block, keystream);

            Array.Copy(block, 0, result, blockStart, Math.Min(result.Length - blockStart, blocksize));
            return result;
        }
        static byte[] editOracle(BlockCipherResult cipherAndNonce, int offset, byte[] replacement) {
            byte[] plain = Set3.encryptOrDecryptAesCtr(cipherAndNonce, fixedKey);
            byte[] result = new byte[Math.Max(cipherAndNonce.Length, offset + replacement.Length)];
            Array.Copy(plain, result, plain.Length);
            Array.Copy(replacement, 0, result, offset, replacement.Length);
            return Set3.encryptOrDecryptAesCtr(result, fixedKey, cipherAndNonce.Iv);
        }
    }
}
