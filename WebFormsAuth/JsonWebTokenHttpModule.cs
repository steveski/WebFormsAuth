using System;
using System.Configuration;
using System.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;
using System.Linq;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Web;
using Newtonsoft.Json;

// https://weblogs.asp.net/imranbaloch/aspnet-webforms-identityserver3
namespace WebFormsAuth
{
    public class JsonWebTokenHttpModule : IHttpModule
    {
        private string _authority = ConfigurationManager.AppSettings["Authority"];


        public void Init(HttpApplication context)
        {
            context.AuthenticateRequest += ContextAuthenticateRequest;
        }

        private void ContextAuthenticateRequest(object sender, EventArgs e)
        {
            var context = HttpContext.Current;
            var request = context.Request;
            var authorizationHeader = request.Headers["Authorization"];

            if (string.IsNullOrWhiteSpace(authorizationHeader) || !authorizationHeader.StartsWith("Bearer "))
                return;

            var token = authorizationHeader.Substring("Bearer ".Length);
            try
            {
                ValidateTokenAndSetIdentity(token);
            }
            catch (SecurityTokenValidationException ex)
            {

            }
            //catch (Exception)
            //{

            //}
        }

        private void ValidateTokenAndSetIdentity(string token)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var validationParameters = GetValidationParameters(tokenHandler);
        }

        private TokenValidationParameters GetValidationParameters(JwtSecurityTokenHandler tokenHandler)
        {
            var securityKey = GetSecurityKey();
            var bytes = Convert.FromBase64String(securityKey);
            var token = new X509SecurityToken(new X509Certificate2(bytes));

            
            return new TokenValidationParameters
            {
                ValidAudience = $"{_authority}/resources",
                ValidIssuer = _authority,
                IssuerSigningKeyResolver = (tkn, securityToken, kid, validationParameters) => token.SecurityKeys.First(),
                IssuerSigningToken = token

            };
        }

        private string GetSecurityKey()
        {
            var client = new WebClient();
            var endpoint = $"{_authority}/.well-known/openid-configuration";
            var json = client.DownloadString(endpoint);
            var metadata = JsonConvert.DeserializeObject<dynamic>(json);
            var jwksUri = metadata.jwks_uri.Value;
            var key = JsonConvert.DeserializeObject<dynamic>(json).keys[0];

            return (string)key.x5c[0];
        }

        public void Dispose()
        {
            
        }
    }
}