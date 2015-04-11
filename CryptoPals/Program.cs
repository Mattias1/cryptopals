using System;

namespace CryptoPals
{
    class Program
    {
        static void Main(string[] args) {
            Console.WriteLine("Crypto pals challenges output:");

            byte[] a = Helpers.FromHexString("1c0111001f010100061a024b53535009181c");
            byte[] b = Helpers.FromHexString("686974207468652062756c6c277320657965");
            string result = Helpers.ToHexString(Helpers.XOR(a, b));
            Console.WriteLine(result);

            Console.ReadLine();
        }
    }
}
