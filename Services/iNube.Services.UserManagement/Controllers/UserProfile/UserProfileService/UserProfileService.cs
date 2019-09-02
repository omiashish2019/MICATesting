using AutoMapper;
using iNube.Services.UserManagement.Entities;
using iNube.Services.UserManagement.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using Microsoft.EntityFrameworkCore;
using iNube.Utility.Framework.Notification;
using System.Threading.Tasks;
using iNube.Utility.Framework.Model;
using iNube.Services.UserManagement.Helpers;

namespace iNube.Services.UserManagement.Controllers.UserProfile.UserProfileService
{
    public interface IUserProfileService
    {
        IEnumerable<ddDTO> GetMaster(string lMasterlist, ApiContext apiContext);
        IEnumerable<ddDTO> GetLocation(string locationType, int parentID, ApiContext apiContext);
        UserResponse CreateProfileUser(UserDTO user, ApiContext apiContext);
        EmployeeDTO CreateProfileemployee(EmployeeDTO emp, ApiContext apiContext);
        TblUserDetails GetUserByUserId(string Id, ApiContext apiContext);
        UserDTO ChangeEmailId(UserDTO _userDTO, ApiContext apiContext);
        UserDTO ChangeMobileNumber(UserDTO _userDTO, ApiContext apiContext);
        UserDTO ModifyUser(UserDTO usersDTOs, ApiContext apiContext);
        IEnumerable<UserDetailsDTO> SearchUser(UserSearchDTO searchRequest, ApiContext apiContext);
        EmployeeDTO SearchEmployee(int Empid, ApiContext apiContext);
        Task<bool> SendEmailAsync(EmailTest emailTest);
        UserDTO SearchUserById(string userId, ApiContext apiContext);
        PasswordResponse ChangePassword(Password pass, ApiContext apiContext);
        VerifyOTPResponse VerifyingOTP(VerifyOTP onetp, ApiContext apiContext);
        Task<SendOtpResponse> SendOTP(SendOtp sendOtp, ApiContext apiContext);
        Task<SendOtpResponse> ResetOTP(SendOtp sendOtp, ApiContext apiContext);
        UserEmailResponse UserEmailValidations(string emailid, ApiContext apiContext);
        String DeleteUserById(string Id,ApiContext apiContext);
    }

    public class UserProfileService : IUserProfileService
    {
        private MICAUMContext _context;
        private IMapper _mapper;
        private bool Result;
        public static int otpvalue { get; set; }
        private readonly IEmailService _emailService;
        private readonly Func<string, IUserProductService> _userproductService;
        public UserProfileService(Func<string, IUserProductService> userproductService, IMapper mapper, IEmailService emailService)
        {
             _mapper = mapper;
            _emailService = emailService;
            _userproductService = userproductService;

        }

        public TblUserDetails GetUserByUserId(string Id, ApiContext apiContext)
        {
            return _userproductService(apiContext.ProductType).GetUserByUserId(Id, apiContext);
        }

        public UserDTO SearchUserById(string userId, ApiContext apiContext)
        {
            return _userproductService(apiContext.ProductType).SearchUserById(userId, apiContext);
        }

        public UserResponse CreateProfileUser(UserDTO user, ApiContext apiContext)
        {
            return _userproductService(apiContext.ProductType).CreateProfileUser(user, apiContext);
        }
        //public UserDTO CreateProfileUser(UserDTO user)
        //{
        //    //  var userDetail = user.TblUserDetails.First();
        //    AspNetUsers _users = _mapper.Map<AspNetUsers>(user);
        //    _users.Id = Guid.NewGuid().ToString();
        //    DateTime now = DateTime.Now;
        //    _users.LockoutEnd = now;
        //    _context.AspNetUsers.Add(_users);
        //    _context.SaveChanges();
        //    var _usersDTOs = _mapper.Map<UserDTO>(_users);
        //    return _usersDTOs;
        //}

        public EmployeeDTO CreateProfileemployee(EmployeeDTO emp, ApiContext apiContext)
        {
            return _userproductService(apiContext.ProductType).CreateProfileemployee(emp, apiContext);
        }

        public UserDTO ChangeEmailId(UserDTO userDTO, ApiContext apiContext)
        {
            return _userproductService(apiContext.ProductType).ChangeEmailId(userDTO, apiContext);
        }

        public UserDTO ChangeMobileNumber(UserDTO userDTO, ApiContext apiContext)
        {
            return _userproductService(apiContext.ProductType).ChangeMobileNumber(userDTO, apiContext);
        }

        public IEnumerable<UserDetailsDTO> SearchUser(UserSearchDTO searchRequest, ApiContext apiContext)
        {
            return _userproductService(apiContext.ProductType).SearchUser(searchRequest, apiContext);
        }

        public EmployeeDTO SearchEmployee(int Empid, ApiContext apiContext)
        {
            return _userproductService(apiContext.ProductType).SearchEmployee(Empid, apiContext);
        }

        public UserDTO ModifyUser(UserDTO usersDTOs, ApiContext apiContext)
        {
            return _userproductService(apiContext.ProductType).ModifyUser(usersDTOs, apiContext);
        }

        //get for master
        public IEnumerable<ddDTO> GetMaster(string lMasterlist, ApiContext apiContext)
        {
            return _userproductService(apiContext.ProductType).GetMaster(lMasterlist, apiContext);
        }

        // get Location
        public IEnumerable<ddDTO> GetLocation(string locationType, int parentID, ApiContext apiContext)
        {
            return _userproductService(apiContext.ProductType).GetLocation(locationType, parentID, apiContext);
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

        public PasswordResponse ChangePassword(Password pass, ApiContext apiContext)
        {
            return _userproductService(apiContext.ProductType).ChangePassword(pass, apiContext);
        }

        public async Task<SendOtpResponse> SendOTP(SendOtp sendOtp, ApiContext apiContext)
        {
            return await _userproductService(apiContext.ProductType).SendOTP(sendOtp, apiContext);
        }

        public async Task<SendOtpResponse> ResetOTP(SendOtp sendOtp, ApiContext apiContext)
        {
            return await _userproductService(apiContext.ProductType).ResetOTP(sendOtp, apiContext);
        }

        public VerifyOTPResponse VerifyingOTP(VerifyOTP onetp, ApiContext apiContext)
        {
            return _userproductService(apiContext.ProductType).VerifyingOTP(onetp, apiContext);
        }

        public UserEmailResponse UserEmailValidations(string emailid, ApiContext apiContext)
        {
            return _userproductService(apiContext.ProductType).UserEmailValidations(emailid, apiContext);
        }
        public String DeleteUserById(string Id, ApiContext apiContext)
        {
            return _userproductService(apiContext.ProductType).DeleteUserById(Id, apiContext);
        }
    }
}
