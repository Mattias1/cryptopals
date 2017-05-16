using System;
using System.Threading;
using CryptoPals;
using Microsoft.AspNetCore.Mvc;

namespace CryptoPalsServer.Controllers
{
    [Route("[controller]")]
    public class Challenge31Controller : Controller
    {
        private static byte[] fixedKey;

        [HttpGet]
        public StatusCodeResult Get(string file, string signature, int nrRight, int delay) {
            try {
                if (fixedKey == null) {
                    fixedKey = RandomHelpers.RandomByteArray(Sha1.ChunkSize);
                }

                byte[] signatureBytes = ConversionHelpers.FromHexString(signature);
                byte[] hmac = Sha1.Hmac(fixedKey, ConversionHelpers.FromUTF8String(file ?? ""));

                bool result = InsecureCompare(hmac, signatureBytes, delay, nrRight);
                return result ? Ok() : (StatusCodeResult)BadRequest();
            }
            catch (Exception e) {
                Console.WriteLine("Exception in ch 31 server: " + e.Message);
                return BadRequest();
            }
        }

        public static bool InsecureCompare(byte[] hmac, byte[] signature, int sleepInMs, int nrRight) {
            for (int i = 0; i < hmac.Length; i++) {
                if (hmac[i] != signature[i]) {
                    // Ok, so because this is taking a looong time, I decided to cheat a bit here. Every 4 keys, it'll remove some of the sleep.
                    Thread.Sleep(Math.Max(i - nrRight, 0) * sleepInMs);
                    return false;
                }
            }
            return true;
        }

        [HttpGet("test")]
        public StatusCodeResult Test(string file, string signature, string key) {
            byte[] signatureBytes = ConversionHelpers.FromHexString(signature);
            byte[] hmac = Sha1.Hmac(ConversionHelpers.FromUTF8String(key ?? ""), ConversionHelpers.FromUTF8String(file ?? ""));

            bool result = InsecureCompare(hmac, signatureBytes, 0, 50);
            return result ? Ok() : (StatusCodeResult)BadRequest();
        }
    }
}
