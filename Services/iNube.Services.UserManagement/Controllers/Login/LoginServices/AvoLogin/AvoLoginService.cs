using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using AutoMapper;
using iNube.Services.UserManagement.Entities.AVO;
using iNube.Services.UserManagement.Helpers;
using iNube.Services.UserManagement.Models;
using iNube.Utility.Framework.Model;
using iNube.Utility.Framework.Notification;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace iNube.Services.UserManagement.Controllers.Login.LoginServices.MicaLogin
{
    public class AvoLoginService : ILoginProductService
    {
        private AVOUMContext _context;
        private bool Result;
        private IMapper _mapper;
        private readonly AppSettings _appSettings;
        public static int? logincount { get; set; }
        public IConfiguration _config;
        private readonly IEmailService _emailService;
        public AvoLoginService(IMapper mapper, IOptions<AppSettings> appSettings, IConfiguration configuration, IEmailService emailService)
        {
            _mapper = mapper;
            _appSettings = appSettings.Value;
            _config = configuration;
            _emailService = emailService;
        }

        public AspNetUsersDTO Authenticate(LoginDTO loginDTO)
        {
            _context = (AVOUMContext)DbManager.GetContext(loginDTO.ProductType, loginDTO.ServerType);
            var user = _context.AspNetUsers.SingleOrDefault(x => x.UserName == loginDTO.Username);

            // check if username exists
            if (user == null)
                return null;

            byte[] passwordSalt = new byte[] { 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20 };

            //// check if password is correct
            if (!Utilities.VerifyPasswordHash(loginDTO.Password, user.PasswordHash, passwordSalt))
                return null;

            // authentication successful
            AspNetUsersDTO userDTO = _mapper.Map<AspNetUsersDTO>(user);
            return userDTO;
            //  return new LoginResponse { Status = BusinessStatus.Created, log = user, ResponseMessage = $"Product code {user.Username} created successfully!! " };

        }

        public bool GoogleValidate(AspNetUsersDTO asp, string productType, string serverType)
        {

            var VerifyGmail = _context.AspNetUsers.SingleOrDefault(x => x.Email == asp.Email);

            try
            {
                if (VerifyGmail.Email == null)
                {
                    VerifyGmail.Email = "WrongEmail";
                }
                bool result = (VerifyGmail.Email == asp.Email);

                if (result)
                {
                    Result = true;
                }
                else
                {
                    Result = false;
                }
            }
            catch (Exception ex)
            {

            }
            return Result;
        }

        public async Task<string> ForgetUserNameAsync(string emailId, string productType, string serverType)
        {
            EmailTest emailTest = new EmailTest();
            var _aspUsers = _context.AspNetUsers.SingleOrDefault(x => x.Email == emailId);
            if (_aspUsers != null)
            {
                string username = _aspUsers.UserName;
                emailTest.To = emailId;
                emailTest.Subject = "MICA Username";
                emailTest.Message = "Dear User,\n" + "      " + "\n" + "      Your Username: " + username + "      " + "\n" + "\nThanks & Regards:\n" + "      " + "MICA Team";
                await SendEmailAsync(emailTest);
                return _aspUsers.UserName;
            }
            else
            {
                return null;
            }
        }

        public async Task<bool> SendEmailAsync(EmailTest emailTest)
        {
            try
            {
                await _emailService.SendEmail(emailTest.To, emailTest.Subject, emailTest.Message);
            }
            catch (Exception ex)
            {

                throw;
            }
            return true;
        }

        public UserLoginResponse GetUserType(string username, string productType, string serverType)
        {
            UserLoginType userLoginType = new UserLoginType();
            _context = (AVOUMContext)DbManager.GetContext(productType, serverType);
            // _context = new AVOUMContext(DbManager.GetDbConnectionString(productType));
            var user = _context.AspNetUsers.SingleOrDefault(x => x.UserName == username);

            if (user != null)
            {
                userLoginType.IsFirstTimeLogin = user.FirstTimeLogin;
                userLoginType.Id = user.Id;
                var loginProvider = _context.AspNetUserTokens.Where(x => x.UserId == user.Id).FirstOrDefault();
                if (loginProvider != null)
                {
                    userLoginType.LoginProvider = loginProvider.LoginProvider;
                }
                else
                {
                    userLoginType.LoginProvider = "Form";

                }

                //userLoginType.Status = BusinessStatus.Ok;
                return new UserLoginResponse { Status = BusinessStatus.Ok, userLogin = userLoginType, Id = userLoginType.IsFirstTimeLogin.ToString(), ResponseMessage = $"UserName Exist" };
            }
            else
            {
                return new UserLoginResponse { Status = BusinessStatus.NotFound, ResponseMessage = $"UserName does not Exist" };
            }

        }

        public LoginResponse GenerateToken(AspNetUsersDTO user, string productType, string serverType)
        {
            LoginResponse loginResponse = new LoginResponse();
            _context = (AVOUMContext)DbManager.GetContext(productType, serverType);
            var userDetails = _context.TblUserDetails.FirstOrDefault(u => u.UserName == user.UserName);
            //var roleDetails = from ro in _context.AspNetRoles
            //                  join ur in _context.AspNetUserRoles on ro.Id equals ur.RoleId
            //                  where ur.UserId == user.Id
            //                  select ur;
            var roleName = _context.AspNetRoles.FirstOrDefault(u => u.Id == userDetails.RoleId).Name;
            var issuer = _config["Jwt:Issuer"];
            var audience = _config["Jwt:Audience"];
            var expiry = DateTime.Now.AddMinutes(120);
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["Jwt:Key"]));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);
            // Add standard claims
            var claims = new List<Claim>
            {
                new Claim("UserId", user.Id),
                new Claim("Email", user.Email),
                new Claim("OrgId",Convert.ToString(userDetails.OrganizationId)),
                new Claim("PartnerId",Convert.ToString(userDetails.PartnerId)),
                new Claim("Role",roleName),
                new Claim("Name",userDetails.FirstName),
                new Claim("UserName",userDetails.UserName),
                new Claim("ProductType",productType),
                new Claim("ServerType",serverType),
            };
            var token = new JwtSecurityToken(issuer: issuer, audience: audience, claims: claims,
                expires: DateTime.Now.AddMinutes(120), signingCredentials: credentials);

            var tokenHandler = new JwtSecurityTokenHandler();
            var stringToken = tokenHandler.WriteToken(token);
            loginResponse.Token = stringToken;
            loginResponse.UserId = user.Id;
            loginResponse.RoleId = userDetails.RoleId;
            loginResponse.UserName = user.UserName;
            loginResponse.FirstName = userDetails.FirstName;
            loginResponse.LastName = userDetails.LastName;
            loginResponse.IsMale = userDetails.GenderId == 1001 ? true : false;
            loginResponse.DisplayName = loginResponse.FirstName + "  " + loginResponse.LastName;
            loginResponse.Status = BusinessStatus.Ok;
            return loginResponse;
        }


    }
}
