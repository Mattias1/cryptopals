using System;
using System.IO;
using System.Linq;
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

            using (var cipher = Aes.Create()) {
                cipher.Mode = mode;
                cipher.Padding = paddingMode == PaddingMode.PKCS7 ? PaddingMode.None : paddingMode;

                try {
                    using (ICryptoTransform decryptor = cipher.CreateDecryptor(key, iv)) {
                        using (MemoryStream from = new MemoryStream(input)) {
                            using (CryptoStream reader = new CryptoStream(from, decryptor, CryptoStreamMode.Read)) {
                                result = new byte[input.Length];
                                reader.Read(result, 0, result.Length);
                            }
                        }
                    }
                }
                catch (Exception ex) {
                    throw ex;
                }
            }
            if (paddingMode == PaddingMode.PKCS7) {
                return UnPKCS7(result);
            }
            return result;
        }

        public static BlockCipherResult Result(byte[] cipher, byte[] iv) {
            return new BlockCipherResult(cipher, iv);
        }

        public static byte[] PKCS7(byte[] raw, int blocksize = 16) {
            // Add PKCS#7 padding
            return ByteArrayHelpers.ForcePadWith(raw, blocksize, (byte)(blocksize - raw.Length % blocksize));
        }

        public static byte[] UnPKCS7(byte[] raw) {
            // Remove PKCS#7 padding. Note that the .NET AES doesn't really unpad, it just replaces them with zeroes.
            int paddingLength = GetPKCS7(raw);
            return ByteArrayHelpers.CopyPartOf(raw, 0, raw.Length - paddingLength);
        }

        public static byte[] ZeroPKCS7(byte[] raw) {
            // Remove PKCS#7 padding. This time, overwrite the padding with zeroes, just like the .NET AES.
            int paddingLength = GetPKCS7(raw);
            byte[] result = new byte[raw.Length];
            Array.Copy(raw, 0, result, 0, raw.Length - paddingLength);
            return result;
        }

        public static int GetPKCS7(byte[] raw) {
            // Check whether or not the raw array is a properly PKCS7-padded. Return -1 when not valid.
            int paddingLength = raw.Last();
            for (int i = 0; i < paddingLength; i++)
                if (raw[raw.Length - i - 1] != paddingLength)
                    return -1;
            return paddingLength;
        }

        public static bool CheckPKCS7(byte[] raw) {
            return GetPKCS7(raw) > 0;
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
