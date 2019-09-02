using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using iNube.Services.UserManagement.Models;
using iNube.Services.UserManagement.Controllers.Login.LoginServices;
using AutoMapper;
using iNube.Services.UserManagement.Helpers;
using Microsoft.Extensions.Options;
using System.IdentityModel.Tokens.Jwt;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using iNube.Services.UserManagement.Entities;
using iNube.Utility.Framework;

namespace iNube.Services.UserManagement.Controllers.Login
{
    [Route("api/[controller]/[action]")]
    [ApiController]
    public class LoginController : BaseApiController
    {
        private ILoginService _loginService;
        private IMapper _mapper;
        private readonly AppSettings _appSettings;
        private static string Secret = "XCAP05H6LoKvbRRa/QkqLNMI7cOHguaRyHzyg7n5qEkGjQmtBhz4SzYh4Fqwjyi3KJHlSXKPwVu2+bXr6CtpgQ==";

        public LoginController(
            ILoginService loginService,
            IMapper mapper,
            IOptions<AppSettings> appSettings)
        {
            _loginService = loginService;
            _mapper = mapper;
            _appSettings = appSettings.Value;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="loginDTO"></param>
        /// <returns></returns>
        // POST: api/Login/Authenticate
        [HttpPost]
        public IActionResult Authenticate([FromBody]LoginDTO loginDTO)
        {
            
            var user = _loginService.Authenticate(loginDTO);

            if (user == null)
                return BadRequest(new LoginResponse{ Status=iNube.Utility.Framework.Model.BusinessStatus.NotFound, ResponseMessage = "Username or password is incorrect" });

            var response = _loginService.GenerateToken(user, loginDTO.ProductType, loginDTO.ServerType);

            // return basic user info (without password) and token to store client side
            return Ok(response);
        }
        
        // POST: api/Login/GoogleValidate
        [AllowAnonymous]
        [HttpPost]
        public IActionResult GoogleValidate([FromBody] AspNetUsersDTO asp, string productType, string serverType)
        {
            var result = _loginService.GoogleValidate(asp,productType,serverType);
            if (result == true)
            {
                return Ok(true);
            }
            else
            {
                return BadRequest(false);
            }
            
        }



        // POST: api/Login/Logout
        [HttpPost]
        public string Logout([FromBody] string value)
        {
            return "True";
        }

         // GET: api/Login/GetUserTypeByUserName
        [HttpGet]
        public IActionResult GetUserType(string username,string productType, string serverType)
        {
            var usrtype = _loginService.GetUserType(username, productType, serverType);
            return Ok(usrtype);
        }

        // GET: api/Login/GenerateToken
        [HttpGet]
        public string GenerateToken(string username)
        {
            var key = Encoding.ASCII.GetBytes(_appSettings.Secret);
            JwtSecurityTokenHandler handler = new JwtSecurityTokenHandler();

            SymmetricSecurityKey securityKey = new SymmetricSecurityKey(key);
           

            SecurityTokenDescriptor descriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new[] {
                    new Claim(ClaimTypes.Name, username)}),

                Expires = DateTime.Now.AddMinutes(30),

                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key),
                SecurityAlgorithms.HmacSha256Signature)
            };

            JwtSecurityToken token = handler.CreateJwtSecurityToken(descriptor);
            token.Payload["username"] = username;
            return handler.WriteToken(token);
        }

        [HttpGet]
        public IActionResult GetUserName(string email,string productType, string serverType)
        {
            var response = _loginService.ForgetUserNameAsync(email, productType,serverType);
            return Ok(response);
        }

        // POST: api/Login/ValidateToken
        [HttpPost]
        public string ValidateToken([FromBody] string token)
        {
            string username = null;
            ClaimsPrincipal principal = GetPrincipal(token);
            if (principal == null)
                return null;
            ClaimsIdentity identity = null;
            try
            {
                identity = (ClaimsIdentity)principal.Identity;
            }
            catch (NullReferenceException)
            {
                return null;
            }
            Claim usernameClaim = identity.FindFirst(ClaimTypes.Name);
            username = usernameClaim.Value;
            return username;
           
        }
        private  ClaimsPrincipal GetPrincipal(string token)
        {
            try
            {
                JwtSecurityTokenHandler tokenHandler = new JwtSecurityTokenHandler();
                JwtSecurityToken jwtToken = (JwtSecurityToken)tokenHandler.ReadToken(token);

                if (jwtToken == null)
                    return null;

                var key = Encoding.ASCII.GetBytes(_appSettings.Secret);

                TokenValidationParameters parameters = new TokenValidationParameters()
                {
                    RequireExpirationTime = true,
                    ValidateIssuer = false,
                    ValidateAudience = false,
                    IssuerSigningKey = new SymmetricSecurityKey(key)
                };

                SecurityToken securityToken;
                ClaimsPrincipal principal = tokenHandler.ValidateToken(token, parameters, out securityToken);
                return principal;
            }
            catch (Exception e)
            {
                return null;
            }
        }
        // GET: api/Login/GetSecurityQ
        [HttpGet]
        public string GetSecurityQ([FromBody] string value)
        {
            return "True";
        }

        // POST: api/Login/ValidateSecurityQ
        [HttpPost]
        public string ValidateSecurityQ([FromBody] string value)
        {
            return "True";
        }

        // POST: api/Login/ForgetPassword
        [HttpPost]
        public string ForgetPassword([FromBody] string value)
        {
            return "True";
        }

        // POST: api/Login/ChangePassword
        [HttpPost]
        public string ChangePassword([FromBody] string value)
        {
            return "True";
        }

        // POST: api/Login/GetUserTypeByUserName
        [HttpPost]
        public string ResetPassword([FromBody] string value)
        {
            return "True";
        }

    }
}
