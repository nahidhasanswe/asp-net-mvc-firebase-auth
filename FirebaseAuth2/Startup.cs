using FirebaseAuth2.Firebase;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Jwt;
using Owin;

[assembly: OwinStartup(typeof(FirebaseAuth2.Startup))]

namespace FirebaseAuth2
{
    public class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            ConfigureFirebaseAuth(app);
        }

        private void ConfigureFirebaseAuth(IAppBuilder app)
        {
            string validAudience = "live-international-staging";
            string validIssuer = $"https://securetoken.google.com/{validAudience}";
            string openIdDiscoveryEndpoint = $"{validIssuer}/.well-known/openid-configuration";

            app.UseJwtBearerAuthentication(new JwtBearerAuthenticationOptions
            {
                AuthenticationMode = AuthenticationMode.Active,
                AllowedAudiences = new[] { validAudience },
                IssuerSecurityKeyProviders = new[]
                {
                    new OpenIdConnectCachingSecurityTokenProvider(openIdDiscoveryEndpoint)
                }
            });
        }
    }
}
