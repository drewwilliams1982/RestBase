using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using IdentityServer3.Core.Configuration;
using IdentityServer3.Core.Models;
using IdentityServer3.Core.Services;
using IdentityServer3.Core.Services.Default;
using Microsoft.Owin;
using Owin;
using IdentityServer3.Core.Services.InMemory;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.OpenIdConnect;
using AuthenticationOptions = IdentityServer3.Core.Configuration.AuthenticationOptions;
using Serilog;
using Serilog.Events;

[assembly: OwinStartup(typeof(RestBase.Startup))]

namespace RestBase
{
    public class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            Log.Logger = new LoggerConfiguration()
                .MinimumLevel.Debug()
                .WriteTo.Trace(LogEventLevel.Debug)
                .CreateLogger();

            ConfigAuth(app);

            app.UseCookieAuthentication(new CookieAuthenticationOptions
            {
                AuthenticationType = "Cookies"
            });
            app.UseOpenIdConnectAuthentication(new OpenIdConnectAuthenticationOptions
            {
                Authority = "https://localhost:44391/identity",
                ClientId = "mvc",
                RedirectUri = "https://localhost:44391/",
                ResponseType = "id_token",
                SignInAsAuthenticationType = "Cookies"
            });
        }

        public void ConfigAuth(IAppBuilder app)
        {
            X509Certificate2 cert = new X509Certificate2(
                $@"{AppDomain.CurrentDomain.BaseDirectory}\bin\Configuration\idsrv3test.pfx", "idsrv3test");
            //                @"c:\cert.pfx", "test1234");

            var users = new List<InMemoryUser>();
            var clients = new List<Client>
            {
                new Client
                {
                    Enabled = true,
                    ClientName = "MVC Client",
                    ClientId = "mvc",
                    Flow = Flows.Implicit,
                    RedirectUris = new List<string>
                    {
                        "https://localhost:44391/"
                    },
                    AllowedScopes = new List<string>() { StandardScopes.OpenId.Name, StandardScopes.Email.Name, StandardScopes.Profile.Name }
                }
            };

            app.Map("/identity", idsrvApp =>
            {
                idsrvApp.UseIdentityServer(new IdentityServerOptions
                {
                    Factory = new IdentityServerServiceFactory
                    {
                        ClientStore = new Registration<IClientStore>(r => new InMemoryClientStore(clients)),
                        UserService = new Registration<IUserService>(r => new InMemoryUserService(users)),
                        ScopeStore = new Registration<IScopeStore>(new InMemoryScopeStore(new[] { StandardScopes.OpenId, StandardScopes.Email, StandardScopes.Profile })),
                        CorsPolicyService = new Registration<ICorsPolicyService>(dr => new DefaultCorsPolicyService() { AllowAll = true })
                    },
                    SiteName = "RestBase Sample",
                    SigningCertificate = cert,
                    AuthenticationOptions = new AuthenticationOptions
                    {
                        CookieOptions = new IdentityServer3.Core.Configuration.CookieOptions
                        {
                            SlidingExpiration = true
                        },
                        EnableLocalLogin = false,
                        EnablePostSignOutAutoRedirect = true,
                        IdentityProviders = ConfigureIdentityProviders
                    }
                });
            });
        }

        private void ConfigureIdentityProviders(IAppBuilder app, string signInAsType)
        {
            string clientId = "50ea9ed9-0171-4b31-80ca-6bc3cb819ab8";
            string redirectUri = "https://localhost:44391/identity/signin-azuread";
            string postLoginRedirectUri = "https://localhost:44391/";
            var options = new OpenIdConnectAuthenticationOptions
            {
                AuthenticationType = "AzureAD",
                Caption = "Sign in with Azure AD",
                Scope = "openid email",
                ClientId = clientId,
                Authority = "https://login.microsoftonline.com/f4da9a3a-6548-4e80-824f-fe48965b3895/", //"v2.0/",

                PostLogoutRedirectUri = postLoginRedirectUri,
                RedirectUri = redirectUri,
                AuthenticationMode = AuthenticationMode.Passive,
                TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = false
                },
                SignInAsAuthenticationType = signInAsType // this must come after tokenvalidationparameters
            };
            app.UseOpenIdConnectAuthentication(options);
        }
    }
}
