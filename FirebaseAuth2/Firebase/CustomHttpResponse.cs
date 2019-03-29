using System.Net;
using System.Net.Http;

namespace FirebaseAuth2.Firebase
{
    public class CustomHttpResponse : HttpResponseMessage
    {
        public CustomHttpResponse(string message, HttpStatusCode statusCode)
        {
            base.Content = new StringContent(message, System.Text.Encoding.UTF8, "text/plain");
            base.StatusCode = statusCode;
        }
    }
}