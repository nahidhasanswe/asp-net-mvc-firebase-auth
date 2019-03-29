using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using System.Web.Security;

namespace FirebaseAuth2.Controllers
{
    public class HomeController : Controller
    {
        public ActionResult Index()
        {
            bool isPersistent = true;
            string username = "nahidhasan";

            FormsAuthenticationTicket ticket = new FormsAuthenticationTicket(
                                                    1,                                     // ticket version
                                                    username,                              // authenticated username
                                                    DateTime.Now,                          // issueDate
                                                    DateTime.Now.AddMinutes(30),           // expiryDate
                                                    isPersistent,                          // true to persist across browser sessions
                                                    "",                              // can be used to store additional user data
                                                    FormsAuthentication.FormsCookiePath);  // the path for the cookie

            // Encrypt the ticket using the machine key
            string encryptedTicket = FormsAuthentication.Encrypt(ticket);

            // Add the cookie to the request to save it
            HttpCookie cookie = new HttpCookie(FormsAuthentication.FormsCookieName, encryptedTicket);
            cookie.HttpOnly = true;
            Response.Cookies.Add(cookie);

            // Your redirect logic
            //Response.Redirect(FormsAuthentication.GetRedirectUrl(username, isPersistent));


            ViewBag.Title = "Home Page";

            return View();
        }

        public ActionResult Verify(string token)
        {
            ViewBag.Token = token;

            var handler = new JwtSecurityTokenHandler();

            // Get Header Access Token
            var jwttoken = handler.ReadToken(token)
                as JwtSecurityToken;

            SecurityToken validatedToken;


            // Validation token information
            var user = handler.ValidateToken(jwttoken.RawData, GetValidationParams(), out validatedToken);



            return View();
        }

        private TokenValidationParameters GetValidationParams()
        {
            return new TokenValidationParameters()
            {
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateLifetime = true,
                ValidateIssuerSigningKey = false,
                ValidIssuer = "https://securetoken.google.com/live-international-staging",
                ValidAudience = "live-international-staging",
                IssuerSigningKeyResolver = new IssuerSigningKeyResolver()
            };
        }
    }
}
