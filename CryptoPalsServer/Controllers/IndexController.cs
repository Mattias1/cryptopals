using Microsoft.AspNetCore.Mvc;

namespace CryptoPalsServer.Controllers
{
    [Route("")]
    public class IndexController : Controller
    {
        [HttpGet]
        public string Get(string file, string signature) {
            return "Cryptopals API";
        }
    }
}
