using System;

namespace CryptoPals
{
    class Program
    {
        static void Main(string[] args) {
            Console.WriteLine("\n Crypto pals challenges output:");
            Console.WriteLine("--------------------------------\n");

            bool result = Set4.challenge30();

            Console.WriteLine("\n--------------------------------");
            Console.WriteLine(result ? " SUCCESS!" : " FAIL!");
            Console.ReadLine();
        }
    }
}
