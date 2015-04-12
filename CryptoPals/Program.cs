using System;

namespace CryptoPals
{
    class Program
    {
        static void Main(string[] args) {
            Console.WriteLine("\n Crypto pals challenges output:");
            Console.WriteLine("--------------------------------\n");

            Challange3();

            Console.WriteLine("\n--------------------------------");
            Console.ReadLine();
        }

        // The challenges
        static bool Challange3() {
            // Crack the message encrypted with a single XOR
            // Input:  1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736
            // Answer: -

            // Inits
            byte[] input = Helpers.FromHexString("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736");
            byte[] key = new byte[1];
            PossiblePlaintext[] scoreList = new PossiblePlaintext[3];

            // Calculate XOR with all possible keys [0, 256)
            for (int k = 0; k < 256; k++) {
                key[0] = (byte)k;
                PossiblePlaintext current = new PossiblePlaintext(Helpers.XOR(input, key));
                current.Score = Helpers.FrequencyScore(current.UTF8String);
                current.InsertInScoreList(scoreList);
            }

            // Display the best plain texts
            for (int i = 0; i < scoreList.Length; i++) {
                Console.WriteLine(i.ToString() + ": " + scoreList[i].UTF8String + " - " + scoreList[i].Score.ToString());
            }

            return scoreList[0].UTF8String == "Cooking MC's like a pound of bacon";
        }

        static bool Challange2() {
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

        static bool Challange1() {
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
