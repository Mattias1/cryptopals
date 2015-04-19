using System;
using System.IO;
using System.Security.Cryptography;

namespace CryptoPals
{
    class Program
    {
        static void Main(string[] args) {
            Console.WriteLine("\n Crypto pals challenges output:");
            Console.WriteLine("--------------------------------\n");

            bool result = challenge7();

            Console.WriteLine("\n--------------------------------");
            Console.WriteLine(result ? " SUCCESS!" : " FAIL!");
            Console.ReadLine();
        }

        // Decrypt AES-ECB using a key
        static bool challenge7() {
            // Input:  The base64 content of the file Data/7.txt
            //         The key is "YELLOW SUBMARINE".
            // Amswer: -

            byte[] input = Helpers.ReadBase64File("Data/7.txt");
            byte[] key = Helpers.FromUTF8String("YELLOW SUBMARINE");

            byte[] result = BlockCipher.Decrypt<AesManaged>(input, key, null, CipherMode.ECB);
            Console.WriteLine(Helpers.ToUTF8String(result));

            return result.Length == 2880;
        }

        // Break a file decrypted with the repeating XOR
        static bool challenge6() {
            // Input:  The base64 content of the file Data/6.txt
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
                current.KeyUsed = BitConverter.GetBytes(keysize);
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
                int keysize = BitConverter.ToInt32(keysizeList[i].KeyUsed, 0);

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
                if (BitConverter.ToInt32(keysizeList[i].KeyUsed, 0) == 29)
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
            // Input:  All strings in file Data/4.txt
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
            byte[] raw = Helpers.FromHexString("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d");
            string result = Convert.ToBase64String(raw);
            Console.WriteLine(result);

            return result == "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";
        }
    }
}
