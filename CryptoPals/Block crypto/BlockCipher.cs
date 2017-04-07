using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace CryptoPals
{
    public static class BlockCipher
    {
        public static byte[] EncryptAES(byte[] input, byte[] key, byte[] iv, CipherMode mode, PaddingMode paddingMode) {
            byte[] result;
            using (var cipher = Aes.Create()) {
                cipher.Mode = mode;
                cipher.Padding = paddingMode;

                using (ICryptoTransform encryptor = cipher.CreateEncryptor(key, iv)) {
                    using (MemoryStream to = new MemoryStream()) {
                        using (CryptoStream writer = new CryptoStream(to, encryptor, CryptoStreamMode.Write)) {
                            writer.Write(input, 0, input.Length);
                            writer.FlushFinalBlock();
                            result = to.ToArray();
                        }
                    }
                }
            }
            return result;
        }

        public static byte[] DecryptAES(byte[] input, byte[] key, byte[] iv, CipherMode mode, PaddingMode paddingMode) {
            byte[] result;
            int decryptedByteCount = 0;

            using (var cipher = Aes.Create()) {
                cipher.Mode = mode;
                cipher.Padding = paddingMode;

                try {
                    using (ICryptoTransform decryptor = cipher.CreateDecryptor(key, iv)) {
                        using (MemoryStream from = new MemoryStream(input)) {
                            using (CryptoStream reader = new CryptoStream(from, decryptor, CryptoStreamMode.Read)) {
                                result = new byte[input.Length];
                                decryptedByteCount = reader.Read(result, 0, result.Length);
                            }
                        }
                    }
                }
                catch (Exception ex) {
                    throw ex;
                }
            }
            return result;
        }

        public static BlockCipherResult Result(byte[] cipher, byte[] iv) {
            return new BlockCipherResult(cipher, iv);
        }
    }

    public class BlockCipherResult
    {
        public byte[] Cipher;
        public byte[] Iv;

        public int Length => this.Cipher.Length;

        public BlockCipherResult(byte[] cipher, byte[] iv) {
            this.Cipher = cipher;
            this.Iv = iv;
        }
    }
}
