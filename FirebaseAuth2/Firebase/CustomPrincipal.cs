using System;
using System.Security.Principal;

namespace FirebaseAuth2.Firebase
{
    public class CustomPrincipal : IPrincipal
    {
        public IIdentity Identity
        {
            get; private set;
        }

        public bool IsInRole(string role)
        {
            throw new NotImplementedException();
        }

        public CustomPrincipal(string username)
        {
            Identity = new GenericIdentity(username);
        }
    }
}