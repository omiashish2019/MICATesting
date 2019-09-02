using iNube.Services.UserManagement.Entities;
using iNube.Services.UserManagement.Models;
using iNube.Utility.Framework.Model;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace iNube.Services.UserManagement.Controllers.UserProfile.UserProfileService
{
    public interface IUserProductService
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
        String DeleteUserById(string Id, ApiContext apiContext);
    }
}
