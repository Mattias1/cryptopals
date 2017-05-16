﻿using System;

namespace CryptoPals
{
    class Program
    {
        static void Main(string[] args) {
            Console.WriteLine("\n Crypto pals challenges output:");
            Console.WriteLine("--------------------------------\n");

            bool result = Set4.challenge32();

            Console.WriteLine("\n--------------------------------");
            Console.WriteLine(result ? " SUCCESS!" : " FAIL!");
            Console.ReadLine();
        }

        private static bool runAll() {
            bool result = true;

            result &= Set1.runSet1();
            result &= Set2.runSet2();
            result &= Set3.runSet3();
            result &= Set4.runSet4();

            return result;
        }
    }
}
