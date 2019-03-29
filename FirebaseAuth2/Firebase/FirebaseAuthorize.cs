using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net;
using System.Security.Claims;
using System.Web.Http;
using System.Web.Http.Controllers;
using System.Web.Http.Filters;

namespace FirebaseAuth2.Firebase
{
    [AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, AllowMultiple = true)]
    public class FirebaseAuthorize : AuthorizationFilterAttribute
    {
        private const string _authorizedToken = "Authorization";

        private string[] AllowedPermissions { get; set; }

        public FirebaseAuthorize()
        {
            AllowedPermissions = null;
        }

        public FirebaseAuthorize(string someFilterParameter)
        {
            AllowedPermissions = someFilterParameter.Split(',');
        }

        public override void OnAuthorization(HttpActionContext filterContext)
        {
            string authorizedToken = string.Empty;
            string userAgent = string.Empty;

            try
            {
                if (!IsSkipAuthentication(filterContext))
                {
                    var principal = filterContext.RequestContext.Principal as ClaimsPrincipal;

                    if (!principal.Identity.IsAuthenticated)
                    {
                        filterContext.Response = new CustomHttpResponse("Access is denied", HttpStatusCode.Unauthorized);
                        return;

                    }
                    else
                    {
                        if (AllowedPermissions != null)
                        {
                            if (!IsAuthorize(filterContext))
                            {
                                filterContext.Response = new CustomHttpResponse("You have no permission", HttpStatusCode.Forbidden);
                                return;
                            }
                        }
                    }
                }
            }
            catch (Exception)
            {
                filterContext.Response = new CustomHttpResponse("You have no permission", HttpStatusCode.Forbidden);
                return;
            }

            base.OnAuthorization(filterContext);
        }

        private bool IsAuthorize(HttpActionContext filterContext)
        {
            // Here is authorization code

            List<string> roles = new List<string>
            {
                "Admin"
            };

            foreach(var role in AllowedPermissions)
            {
                if (roles.Any(r => r.Equals(role)))
                {
                    return true;
                }
            }

            return false;
        }


        private bool IsSkipAuthentication(HttpActionContext filterContext)
        {
            return filterContext.ActionDescriptor.GetCustomAttributes<AllowAnonymousAttribute>().Any()
                         || filterContext.ActionDescriptor.ControllerDescriptor.GetCustomAttributes<AllowAnonymousAttribute>().Any();
        }

        private string GetAuthToken(HttpActionContext filterContext)
        {
            var headerToken = filterContext.Request.Headers.SingleOrDefault(x => x.Key == _authorizedToken);
            return headerToken.Value.SingleOrDefault().Replace("Bearer ", string.Empty);
        }

        private string GetUserEmail(string token)
        {
            var handler = new JwtSecurityTokenHandler();
            var tokenClaims = handler.ReadToken(token) as JwtSecurityToken;
            return tokenClaims.Claims.First(claim => claim.Type == "email").Value;
        }
    }
}