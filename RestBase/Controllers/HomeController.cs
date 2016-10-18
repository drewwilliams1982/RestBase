using System.Security.Claims;
using System.Web.Mvc;

namespace RestBase.Controllers
{
    [Authorize]
    public class HomeController : Controller
    {
        public ActionResult Index()
        {
            return View((User as ClaimsPrincipal).Claims);
        }
    }
}
