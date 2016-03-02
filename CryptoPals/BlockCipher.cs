using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace CryptoPals
{
    public static class BlockCipher
    {
        // Thank you SO: http://stackoverflow.com/questions/273452/using-aes-encryption-in-c-sharp

        public static byte[] EncryptAES(byte[] input, byte[] key, byte[] iv, CipherMode mode, PaddingMode paddingMode) {
            return EncryptGeneral<AesManaged>(input, key, iv, mode, paddingMode);
        }
        public static byte[] EncryptGeneral<T>(byte[] input, byte[] key, byte[] iv, CipherMode mode, PaddingMode paddingMode)
                where T : SymmetricAlgorithm, new() {
            byte[] result;
            using (T cipher = new T()) {
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
                cipher.Clear();
            }
            return result;
        }


        public static byte[] DecryptAES(byte[] input, byte[] key, byte[] iv, CipherMode mode, PaddingMode paddingMode) {
            return DecryptGeneral<AesManaged>(input, key, iv, mode, paddingMode);
        }
        public static byte[] DecryptGeneral<T>(byte[] input, byte[] key, byte[] iv, CipherMode mode, PaddingMode paddingMode)
            where T : SymmetricAlgorithm, new() {
            byte[] result;
            int decryptedByteCount = 0;

            using (T cipher = new T()) {
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

                cipher.Clear();
            }
            return result;
        }


        public static BlockCipherResult Result(byte[] cipher, byte[] iv) {
            return new BlockCipherResult(cipher, iv);
        }
    }

    public class BlockCipherResult
    {
        public BlockCipherResult(byte[] cipher, byte[] iv) {
            this.Cipher = cipher;
            this.Iv = iv;
        }

        public byte[] Cipher;
        public byte[] Iv;
    }
}
