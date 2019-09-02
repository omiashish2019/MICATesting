using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using AutoMapper;
using iNube.Services.UserManagement.Entities;
using iNube.Services.UserManagement.Helpers;
using iNube.Services.UserManagement.Models;
using iNube.Utility.Framework.Model;
using iNube.Utility.Framework.Notification;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace iNube.Services.UserManagement.Controllers.Login.LoginServices
{
    public interface ILoginService
    {
        AspNetUsersDTO Authenticate(LoginDTO loginDTO);
        bool GoogleValidate(AspNetUsersDTO asp,  string productType, string serverType);
        Task<string> ForgetUserNameAsync(string emailId, string productType, string serverType);
        UserLoginResponse GetUserType(string username, string productType, string serverType);
        LoginResponse GenerateToken(AspNetUsersDTO user, string productType, string serverType);
        Task<bool> SendEmailAsync(EmailTest emailTest);
    }

    public class LoginService : ILoginService
    {
        //private MICAUMContext _context;
        private bool Result;
        private IMapper _mapper;
        private readonly AppSettings _appSettings;
        public static int? logincount { get; set; }
        public IConfiguration _config;
        private readonly IEmailService _emailService;
        private readonly Func<string, ILoginProductService> _loginService;
        public LoginService(Func<string, ILoginProductService> loginService,IMapper mapper, IOptions<AppSettings> appSettings,  IConfiguration configuration, IEmailService emailService)
        {
            _mapper = mapper;
            _appSettings = appSettings.Value;
            _config = configuration;
            _emailService = emailService;
            _loginService = loginService;
            var avoConnectionstring = _config.GetConnectionString("AVOUMConnection");
            // services.AddDbContext<AVOUMContext>(x => x.UseSqlServer(avoConnectionstring));
            //DbContextOptions<MICAUMContext> options = new DbContextOptions<MICAUMContext>(SqlServerDbContextOptionsExtensions);
            //options.
            //DbContextOptions<MICAUMContext> dbContextOption =(DbContextOptions<MICAUMContext>) SqlServerDbContextOptionsExtensions.UseSqlServer(new DbContextOptionsBuilder(), avoConnectionstring).Options;
            //_context = new MICAUMContext(dbContextOption);
        }

        public AspNetUsersDTO Authenticate(LoginDTO loginDTO)
        {
            // Set DbName for DbManager.
            DbManager.DbName = loginDTO.ProductType;
            if (string.IsNullOrEmpty(loginDTO.Username) || string.IsNullOrEmpty(loginDTO.Password))
                return null;

           return  _loginService(loginDTO.ProductType).Authenticate(loginDTO);
        }

        public bool GoogleValidate(AspNetUsersDTO asp, string productType, string serverType)
        {
            return _loginService(productType).GoogleValidate(asp, productType, serverType);

            //var VerifyGmail = _context.AspNetUsers.SingleOrDefault(x => x.Email == asp.Email);

            //try
            //{
            //    if (VerifyGmail.Email == null)
            //    {
            //        VerifyGmail.Email = "WrongEmail";
            //    }
            //    bool result = (VerifyGmail.Email == asp.Email);

            //    if (result)
            //    {
            //        Result = true;
            //    }
            //    else
            //    {
            //        Result = false;
            //    }
            //}
            //catch (Exception ex)
            //{

            //}
            //return Result;
        }

        public async Task<string> ForgetUserNameAsync(string emailId, string productType,string serverType)
        {
            return await _loginService(productType).ForgetUserNameAsync(emailId, productType, serverType);
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
           return  _loginService(productType).GetUserType(username, productType, serverType);
        }

       
        public LoginResponse GenerateToken(AspNetUsersDTO user, string productType, string serverType)
        {
           return  _loginService(productType).GenerateToken(user, productType,serverType);
        }
    }
}
