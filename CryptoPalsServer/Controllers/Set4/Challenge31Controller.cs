using Microsoft.AspNetCore.Mvc;

namespace WebApplication1.Controllers
{
    [Route("[controller]")]
    public class Challenge31Controller : Controller
    {
        [HttpGet]
        public string Get(string file, string signature) {
            return $"file: {file}, signature: {signature}";
        }
    }
}
