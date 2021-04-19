using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;

namespace CookiesTest.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class WeatherForecastController : ControllerBase
    {
        private static readonly string[] Summaries = new[]
        {
            "Freezing", "Bracing", "Chilly", "Cool", "Mild", "Warm", "Balmy", "Hot", "Sweltering", "Scorching"
        };

        private readonly ILogger<WeatherForecastController> _logger;
        private IConfiguration _config;

        public WeatherForecastController(ILogger<WeatherForecastController> logger, IConfiguration config)
        {
            _logger = logger;
            _config = config;
        }

        [HttpGet]
        [Authorize]
        public IEnumerable<WeatherForecast> Get()
        {
            var rng = new Random();
            return Enumerable.Range(1, 5).Select(index => new WeatherForecast
            {
                Date = DateTime.Now.AddDays(index),
                TemperatureC = rng.Next(-20, 55),
                Summary = Summaries[rng.Next(Summaries.Length)]
            })
            .ToArray();
        }




        [HttpPost("login")]
        public IActionResult Login([FromBody] UserModel login)
        {
            IActionResult response = Unauthorized();
            var user = AuthenticateUser(login);

            if (user != null)
            {
                var token = GenerateJSONWebToken(user);
                var tokenString = new JwtSecurityTokenHandler().WriteToken(token);


                var ipAddress = IPAddress();
                var refreshToken = generateRefreshToken(ipAddress);

                setTokenCookie(refreshToken.Token, "refreshToken");
                setTokenCookie(tokenString, "AccessToken", token.ValidTo);




                response = Ok(new { token = tokenString, expiration = token.ValidTo });
            }

            return response;
        }


        public void setTokenCookie(string token, string key, DateTime? validTo = null)
        {
            var cookieOptions = new CookieOptions
            {
                HttpOnly = true,
                Expires = validTo == null ? DateTime.UtcNow.AddDays(7) : validTo
            };
            Response.Cookies.Append(key, token, cookieOptions);
        }

        private RefreshToken generateRefreshToken(string ipAddress)
        {
            using (var rngCryptoServiceProvider = new RNGCryptoServiceProvider())
            {
                var randomBytes = new byte[64];
                rngCryptoServiceProvider.GetBytes(randomBytes);
                return new RefreshToken
                {
                    Token = Convert.ToBase64String(randomBytes),
                    Expires = DateTime.UtcNow.AddDays(7),
                    Created = DateTime.UtcNow,
                    CreatedByIp = ipAddress
                };
            }
        }


        private string IPAddress()
        {
            if (Request.Headers.ContainsKey("X-Forwarded-For"))
                return Request.Headers["X-Forwarded-For"];
            else
                return HttpContext.Connection.RemoteIpAddress.MapToIPv4().ToString();
        }

        private JwtSecurityToken GenerateJSONWebToken(UserModel userInfo, int daysAdded = 3)
        {
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["Jwt:Secret"]));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(_config["Jwt:ValidIssuer"],
              _config["Jwt:ValidIssuer"],
              null,
              expires: DateTime.Now.AddDays(daysAdded),
              signingCredentials: credentials);

            return token;
        }

        private UserModel AuthenticateUser(UserModel login)
        {
            UserModel user = null;

            //Validate the User Credentials    
            //Demo Purpose, I have Passed HardCoded User Information    
            if (login.Username == "Dunsin")
            {
                user = new UserModel { Username = "Dunsin", EmailAddress = "test.test@test.com" };
            }
            return user;
        }

        /*await HttpContext.SignOutAsync(
  CookieAuthenticationDefaults.AuthenticationScheme);*/

        [HttpPost("logout")]
        public async Task<IActionResult> LogoutAsync([FromBody] UserModel login)
        {
            IActionResult response = Unauthorized();
            var user = AuthenticateUser(login);

            if (user != null)
            {
                var token = GenerateJSONWebToken(user, -3);
                var tokenString = new JwtSecurityTokenHandler().WriteToken(token);


                //var ipAddress = IPAddress();
                //var refreshToken = generateRefreshToken(ipAddress);

                //setTokenCookie(refreshToken.Token, "refreshToken");
                //setTokenCookie(tokenString, "AccessToken", token.ValidTo);


                await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);

                response = Ok(new { token = tokenString, expiration = token.ValidTo });
            }

            return response;
        }

    }
}
