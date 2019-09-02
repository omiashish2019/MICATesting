using iNube.Services.UserManagement.Entities;
using iNube.Services.UserManagement.Models;
using iNube.Utility.Framework.Model;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace iNube.Services.UserManagement.Controllers.UserProfile.UserProfileService.MotorProfile
{
    public class MotorProfileService : IUserProductService
    {
        public UserDTO ChangeEmailId(UserDTO _userDTO, ApiContext apiContext)
        {
            throw new NotImplementedException();
        }

        public UserDTO ChangeMobileNumber(UserDTO _userDTO, ApiContext apiContext)
        {
            throw new NotImplementedException();
        }

        public PasswordResponse ChangePassword(Password pass, ApiContext apiContext)
        {
            throw new NotImplementedException();
        }

        public EmployeeDTO CreateProfileemployee(EmployeeDTO emp, ApiContext apiContext)
        {
            throw new NotImplementedException();
        }

        public UserResponse CreateProfileUser(UserDTO user, ApiContext apiContext)
        {
            throw new NotImplementedException();
        }

        public string DeleteUserById(string Id, ApiContext apiContext)
        {
            throw new NotImplementedException();
        }

        public IEnumerable<ddDTO> GetLocation(string locationType, int parentID, ApiContext apiContext)
        {
            throw new NotImplementedException();
        }

        public IEnumerable<ddDTO> GetMaster(string lMasterlist, ApiContext apiContext)
        {
            throw new NotImplementedException();
        }

        public TblUserDetails GetUserByUserId(string Id, ApiContext apiContext)
        {
            throw new NotImplementedException();
        }

        public UserDTO ModifyUser(UserDTO usersDTOs, ApiContext apiContext)
        {
            throw new NotImplementedException();
        }

        public Task<SendOtpResponse> ResetOTP(SendOtp sendOtp, ApiContext apiContext)
        {
            throw new NotImplementedException();
        }

        public EmployeeDTO SearchEmployee(int Empid, ApiContext apiContext)
        {
            throw new NotImplementedException();
        }

        public IEnumerable<UserDetailsDTO> SearchUser(UserSearchDTO searchRequest, ApiContext apiContext)
        {
            throw new NotImplementedException();
        }

        public UserDTO SearchUserById(string userId, ApiContext apiContext)
        {
            throw new NotImplementedException();
        }

        public Task<bool> SendEmailAsync(EmailTest emailTest)
        {
            throw new NotImplementedException();
        }

        public Task<SendOtpResponse> SendOTP(SendOtp sendOtp, ApiContext apiContext)
        {
            throw new NotImplementedException();
        }

        public UserEmailResponse UserEmailValidations(string emailid, ApiContext apiContext)
        {
            throw new NotImplementedException();
        }

        public VerifyOTPResponse VerifyingOTP(VerifyOTP onetp, ApiContext apiContext)
        {
            throw new NotImplementedException();
        }
    }
}
