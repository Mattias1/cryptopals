using System;
using System.IO;
using System.Text.RegularExpressions;

namespace CryptoPals
{
    class Program
    {
        static void Main(string[] args) {
            Console.WriteLine("\n Crypto pals challenges output:");
            Console.WriteLine("--------------------------------\n");

            bool result = challenge5();

            Console.WriteLine("\n--------------------------------");
            Console.WriteLine(result ? " SUCCESS!" : " FAIL!");
            Console.ReadLine();
        }

        // The challenges
        static bool challenge5() {
            // Encrypt a message using a repeating XOR
            // Input:  Burning 'em, if you ain't quick and nimble
            //         I go crazy when I hear a cymbal
            // Answer: 0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272
            //         a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f

            // Inits
            string message = "Burning 'em, if you ain't quick and nimble" + "\n" + "I go crazy when I hear a cymbal"; // Using a unix newline!
            byte[] key = Helpers.FromUTF8String("ICE");

            byte[] plain = Helpers.FromUTF8String(message);

            // Encrypt it
            byte[] cipher = Helpers.XOR(plain, key);
            string result = Helpers.ToHexString(cipher);

            // Print the result
            Console.WriteLine(result);

            return result == "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272"
                + "a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";
        }

        static bool challenge4() {
            // Detect the message encrypted with a single XOR
            // Input:  All strings in file Data/4.txt
            // Answer: -

            // Inits
            byte[] key = new byte[1];
            PossiblePlaintext[] scoreList = new PossiblePlaintext[10];

            using (StreamReader reader = new StreamReader("Data/4.txt")) {
                string line;
                while ((line = reader.ReadLine()) != null) {
                    byte[] input = Helpers.FromHexString(line);

                    // Attack
                    attackSingleXOR(input, scoreList);
                }
            }

            // Display the best plain texts
            for (int i = 0; i < scoreList.Length; i++) {
                Console.WriteLine(i.ToString() + ": " + scoreList[i].UTF8String + " - " + scoreList[i].Score.ToString());
            }

            return scoreList[0].UTF8String == "Now that the party is jumping\n";
        }

        static bool challenge3() {
            // Crack the message encrypted with a single XOR
            // Input:  1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736
            // Answer: -

            // Inits
            byte[] input = Helpers.FromHexString("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736");
            PossiblePlaintext[] scoreList = new PossiblePlaintext[5];

            // Display the best plain texts
            for (int i = 0; i < scoreList.Length; i++) {
                Console.WriteLine(i.ToString() + ": " + scoreList[i].UTF8String + " - " + scoreList[i].Score.ToString());
            }

            return scoreList[0].UTF8String == "Cooking MC's like a pound of bacon";
        }

        static void attackSingleXOR(byte[] input, PossiblePlaintext[] scoreList) {
            // Calculate XOR with all possible keys [0, 256) and insert it in the score list
            byte[] key = new byte[1];
            for (int k = 0; k < 256; k++) {
                key[0] = (byte)k;
                PossiblePlaintext current = new PossiblePlaintext(Helpers.XOR(input, key));
                current.Score = Helpers.FrequencyScore(current.UTF8String);
                current.InsertInScoreList(scoreList);
            }
        }

        static bool challenge2() {
            // XOR two byte arrays
            // Input:  1c0111001f010100061a024b53535009181c
            //         686974207468652062756c6c277320657965
            // Answer: 746865206b696420646f6e277420706c6179

            byte[] a = Helpers.FromHexString("1c0111001f010100061a024b53535009181c");
            byte[] b = Helpers.FromHexString("686974207468652062756c6c277320657965");
            string result = Helpers.ToHexString(Helpers.XOR(a, b));
            Console.WriteLine(result);

            return result == "746865206b696420646f6e277420706c6179";
        }

        static bool challenge1() {
            // Read a hex string and output it as base64
            // Input:  49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d
            // Answer: SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t
            byte[] raw = Helpers.FromHexString("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d");
            string result = Convert.ToBase64String(raw);
            Console.WriteLine(result);

            return result == "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";
        }
    }
}
