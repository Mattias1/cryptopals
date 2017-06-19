using System;
using System.Linq;
using System.Numerics;

namespace CryptoPals
{
    public static class DiffieHelman
    {
        public static byte[] P {
            get => ConversionHelpers.FromHexString(
                "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024" +
                "e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd" +
                "3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec" +
                "6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f" +
                "24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361" +
                "c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552" +
                "bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff" +
                "fffffffffffff"
            );
        }
        public static byte[] G => ConversionHelpers.FromUInt(2);

        public static KeyPair GenerateKeypair() => GenerateKeypair(P, G);

        public static KeyPair GenerateKeypair(byte[] p, byte[] g) {
            byte[] privateKey = RandomModP(p);
            byte[] publicKey = ModExp(g, privateKey, p);

            return new KeyPair(publicKey, privateKey);
        }

        private static byte[] RandomModP(byte[] p) {
            var bigP = toBigInt(p);
            BigInteger bigRandom = toBigInt(RandomHelpers.RandomByteArray(p.Length));
            bigRandom = bigRandom % bigP;
            return bigRandom.ToByteArray();
        }

        public static byte[] GenerateSessionKey(byte[] publicKey, byte[] privateKey) => GenerateSessionKey(publicKey, privateKey, P);

        public static byte[] GenerateSessionKey(byte[] publicKey, byte[] privateKey, byte[] p) {
            return ModExp(publicKey, privateKey, p);
        }

        public static uint ModExp(uint base_, uint exponent, uint mod) {
            var b = new BigInteger(base_);
            var e = new BigInteger(exponent);
            var m = new BigInteger(mod);

            var result = ModExp(b, e, m);
            return ConversionHelpers.ToUInt(result.ToByteArray());
        }

        public static byte[] ModExp(byte[] base_, byte[] exponent, byte[] mod) {
            var b = toBigInt(base_);
            var e = toBigInt(exponent);
            var m = toBigInt(mod);

            return ModExp(b, e, m).ToByteArray();
        }

        public static BigInteger ModExp(BigInteger b, BigInteger e, BigInteger m) {
            if (e == 1) return b % m;
            if (e == 0) return 1;
            if (e < 0) throw new ArgumentException("Exponent should be larger or equal then zero");

            BigInteger square = ModExp(b * b % m, e / 2, m);
            return e.IsEven ? square : square * b % m;
        }

        private static BigInteger toBigInt(byte[] bytes) {
            if (bytes.Last() > 0x7f) {
                return new BigInteger(ByteArrayHelpers.Concatenate(bytes, new byte[1]));
            }
            return new BigInteger(bytes);
        }
    }

    public struct KeyPair
    {
        public byte[] PublicKey, PrivateKey;

        public KeyPair(byte[] publicKey, byte[] privateKey) {
            PublicKey = publicKey;
            PrivateKey = privateKey;
        }
    }
}
