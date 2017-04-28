using System.IO;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Builder;

namespace CryptoPalsServer
{
    public class Program
    {
        public static void Main(string[] args) {
            var host = new WebHostBuilder()
                .UseKestrel()
                .UseContentRoot(Directory.GetCurrentDirectory())
                .UseIISIntegration()
                .UseStartup<Startup>();

#if !DEBUG
            host.UseUrls("http://localhost:9000");
#endif

            host.Build().Run();
        }
    }
}
