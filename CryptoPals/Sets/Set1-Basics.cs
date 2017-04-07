using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;

namespace CryptoPals
{
    class Set1 : Set
    {
        // Run all challenges of set 1
        public static bool runSet1() {
            return runSet(1, challenge1, challenge2, challenge3, challenge4, challenge5, challenge6, challenge7, challenge8);
        }

        // Detect ECB mode
        public static bool challenge8() {
            // Input:  All hex strings in file Data/8.txt
            // Answer: -

            // Get the lines with the highest number of equal blocks
            // (this does not guarantee anything, it could be chance, but the probability is probably low xD)
            // (I am really assuming that the plaintext has at least some equal blocks)
            int lineNumber = 0;
            ScoreItem[] scoreList = new ScoreItem[5];
            using (FileStream stream = new FileStream("Data/8.txt", FileMode.Open)) {
                using (StreamReader reader = new StreamReader(stream)) {
                    string line;
                    while ((line = reader.ReadLine()) != null) {
                        // Init
                        lineNumber++;
                        byte[] input = ConversionHelpers.FromHexString(line);
                        byte[][] blocks = ByteArrayHelpers.SplitUp(input, 16);

                        // Count the number of equal blocks .
                        ScoreItem current = new ScoreItem(input);
                        current.KeyUsedInt = lineNumber;
                        for (int i = 0; i < blocks.Length - 1; i++)
                            for (int j = i + 1; j < blocks.Length; j++)
                                if (MiscHelpers.Equals(blocks[i], blocks[j]))
                                    current.Score--;
                        current.InsertInScoreList(scoreList);
                    }
                }
            }

            // Display the best ones
            ScoreItem.DisplayScoreList(scoreList, false);

            return scoreList[0].KeyUsedInt == 133;
        }

        // Decrypt AES-ECB using a key
        public static bool challenge7() {
            // Input:  The base64 encoded content of the file Data/7.txt
            //         The key is "YELLOW SUBMARINE"
            // Amswer: -

            byte[] input = ConversionHelpers.ReadBase64File("Data/7.txt");
            byte[] key = ConversionHelpers.FromUTF8String("YELLOW SUBMARINE");

            byte[] result = BlockCipher.DecryptAES(input, key, null, CipherMode.ECB, PaddingMode.PKCS7);
            ConversionHelpers.PrintUTF8String(result);

            return MiscHelpers.QuickCheck(result, 2880, "I'm back and I'm ringin' the bell"); // Padded with 4 zeroes
        }

        // Break a file decrypted with the repeating XOR
        public static bool challenge6() {
            // Input:  The base64 encoded content of the file Data/6.txt
            // Answer: -

            // Test hamming distance
            byte[] x = ConversionHelpers.FromUTF8String("this is a test");
            byte[] y = ConversionHelpers.FromUTF8String("wokka wokka!!!");
            int hammingDistance = MiscHelpers.HammingDistance(x, y);
            Console.WriteLine("Hamming distance: " + hammingDistance.ToString() + "\n");
            if (hammingDistance != 37)
                return false;

            // Read the file
            byte[] input = ConversionHelpers.ReadBase64File("Data/6.txt");

            // Find the keysize
            int nrOfSamples = 5;
            ScoreItem[] keysizeList = new ScoreItem[3];
            for (int keysize = 2; keysize < 40; keysize++) {
                ScoreItem current = new ScoreItem(input);
                current.KeyUsedInt = keysize;
                for (int i = 0; i < nrOfSamples * 2; i += 2) {
                    byte[] a = ByteArrayHelpers.CopyPartOf(input, keysize * i, keysize);
                    byte[] b = ByteArrayHelpers.CopyPartOf(input, keysize * (i + 1), keysize);
                    current.Score += MiscHelpers.HammingDistance(a, b);
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
                string possibleMessage = ConversionHelpers.ToUTF8String(ByteArrayHelpers.XOR(input, key));
                if (keysize == 29)
                    Console.WriteLine("Keysize: {0}, key: {1}, message: {2}", keysize, ConversionHelpers.ToHexString(key, true), possibleMessage);
            }

            // Return true when one of the tried keysizes is 29 (0x1D)
            return keysizeList.Any(t => t.KeyUsedInt == 29);
        }

        public static byte[] attackRepeatingXOR(byte[] input, int keysize, byte[] keySoFar = null) {
            // Analyze all the blocks that have the same key - attacking each transposed block will give us one byte of the key (using the single XOR attack)
            byte[] key = new byte[keysize];
            if (keySoFar != null)
                Array.Copy(keySoFar, key, keySoFar.Length);

            byte[][] transposed = ByteArrayHelpers.Transpose(ByteArrayHelpers.SplitUp(input, keysize));
            for (int j = keySoFar?.Length ?? 0; j < transposed.Length; j++)
                key[j] = attackSingleXOR(transposed[j]);

            return key;
        }

        // Encrypt a message using a repeating XOR
        public static bool challenge5() {
            // Input:  Burning 'em, if you ain't quick and nimble
            //         I go crazy when I hear a cymbal
            //         Key: ICE
            // Answer: 0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272
            //         a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f

            string message = "Burning 'em, if you ain't quick and nimble" + "\n" + "I go crazy when I hear a cymbal"; // Using a unix newline!
            byte[] key = ConversionHelpers.FromUTF8String("ICE");
            byte[] plain = ConversionHelpers.FromUTF8String(message);

            string result = ConversionHelpers.ToHexString(ByteArrayHelpers.XOR(plain, key));
            Console.WriteLine(result);

            return result == "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272"
                + "a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";
        }

        // Detect (and break) the message encrypted with a single XOR
        public static bool challenge4() {
            // Input:  All hex strings in file Data/4.txt
            // Answer: -

            // Inits
            ScoreItem[] scoreList = new ScoreItem[10];

            using (FileStream stream = new FileStream("Data/4.txt", FileMode.Open)) {
                using (StreamReader reader = new StreamReader(stream)) {
                    string line;
                    while ((line = reader.ReadLine()) != null) {
                        byte[] input = ConversionHelpers.FromHexString(line);

                        // Attack
                        attackSingleXOR(input, scoreList);
                    }
                }
            }

            // Display the best plain texts
            ScoreItem.DisplayScoreList(scoreList);

            return scoreList[0].Utf8String == "Now that the party is jumping\n";
        }

        // Crack the message encrypted with a single XOR
        public static bool challenge3() {
            // Input:  1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736
            // Answer: -
            bool test = true;

            // Inits
            byte[] input = ConversionHelpers.FromHexString("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736");
            ScoreItem[] scoreList = new ScoreItem[5];

            // Attack
            attackSingleXOR(input, scoreList);

            // Display the best plain texts
            ScoreItem.DisplayScoreList(scoreList);

            return scoreList[0].Utf8String == "Cooking MC's like a pound of bacon";
        }

        public static byte attackSingleXOR(byte[] input, ScoreItem[] scoreList) {
            // Calculate XOR with all possible keys [0, 256) and insert it in the score list
            for (int k = 0; k < 256; k++) {
                byte[] key = new byte[1] { (byte)k };
                ScoreItem.InsertFrequencyAnalysis(ByteArrayHelpers.XOR(input, key), key, scoreList);
            }
            return scoreList[0].KeyUsed[0];
        }
        public static byte attackSingleXOR(byte[] input) {
            return attackSingleXOR(input, new ScoreItem[1]);
        }

        // XOR two byte arrays
        public static bool challenge2() {
            // Input:  1c0111001f010100061a024b53535009181c
            //         686974207468652062756c6c277320657965
            // Answer: 746865206b696420646f6e277420706c6179

            byte[] a = ConversionHelpers.FromHexString("1c0111001f010100061a024b53535009181c");
            byte[] b = ConversionHelpers.FromHexString("686974207468652062756c6c277320657965");

            string result = ConversionHelpers.ToHexString(ByteArrayHelpers.XOR(a, b));
            Console.WriteLine(result);

            // Easter eggs - b: "hit the bull's eye", a^b: "the kid don't play"
            return result == "746865206b696420646f6e277420706c6179";
        }

        // Read a hex string and output it as base64
        public static bool challenge1() {
            // Input:  49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d
            // Answer: SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t

            // Easter egg - Input: "I'm killing your brain like a poisenous mushroom"
            byte[] input = ConversionHelpers.FromHexString("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d");
            string result = Convert.ToBase64String(input);
            Console.WriteLine(result);

            return result == "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";
        }
    }
}
