using System.Threading;
using CryptoPals;
using Microsoft.AspNetCore.Mvc;

namespace WebApplication1.Controllers
{
    [Route("[controller]")]
    public class Challenge31Controller : Controller
    {
        private static byte[] fixedKey;

        [HttpGet]
        public StatusCodeResult Get(string file, string signature) {
            if (fixedKey == null) {
                fixedKey = RandomHelpers.RandomByteArray(Sha1.ChunkSize);
            }

            byte[] signatureBytes = ConversionHelpers.FromHexString(signature);
            byte[] hmac = Sha1.Hmac(fixedKey, ConversionHelpers.FromUTF8String(file));

            bool result = InsecureCompare(hmac, signatureBytes, 50);
            return result ? Ok() : (StatusCodeResult)BadRequest();
        }

        public static bool InsecureCompare(byte[] hmac, byte[] signature, int sleepInMs) {
            for (int i = 0; i < hmac.Length; i++) {
                Thread.Sleep(sleepInMs);
                if (hmac[i] != signature[i])
                    return false;
            }
            return true;
        }
    }
}
