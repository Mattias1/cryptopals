using System;

namespace CryptoPals
{
    class Program
    {
        static void Main(string[] args) {
            Console.WriteLine("Crypto pals challenges output:");

            byte[] test = Helpers.FromHexString("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d");
            string result = Convert.ToBase64String(test);
            Console.WriteLine(result);

            Console.ReadLine();
        }
    }
}
