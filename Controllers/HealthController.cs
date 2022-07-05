using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace SocialNetworkProjectBackend.Controllers
{
    [ApiController]
    [Route("api")]
    public class HealthController : ControllerBase
    {
        [HttpPost]
        [Route("health")]
        [AllowAnonymous]
        public IActionResult Health()
        {
            return Ok("ok");
        }
    }
}