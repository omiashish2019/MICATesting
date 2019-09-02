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


namespace iNube.Services.UserManagement.Controllers.UserProfile.UserProfileService.MicaProfile
{
    public class AvoProfileService : IUserProductService
    {
        private MICAUMContext _context;
        private IMapper _mapper;
        private bool Result;
        public static int otpvalue { get; set; }
        private readonly IEmailService _emailService;
        public AvoProfileService(MICAUMContext context, IMapper mapper, IEmailService emailService)
        {
            _context = context;
            _mapper = mapper;
            _emailService = emailService;

        }

        public TblUserDetails GetUserByUserId(string Id, ApiContext apiContext)
        {
            _context = (MICAUMContext)DbManager.GetContext(apiContext.ProductType, apiContext.ServerType);
            var _userDetails = _context.TblUserDetails.SingleOrDefault(x => x.UserId == Id);
            return _userDetails;

        }

        public UserDTO SearchUserById(string userId, ApiContext apiContext)
        {
            _context = (MICAUMContext)DbManager.GetContext(apiContext.ProductType, apiContext.ServerType);
            var _userd = _context.AspNetUsers.Where(user => user.Id == userId)
                        .Include(add => add.TblUserDetails)
                        .Include(add => add.TblUserAddress)
                        .ToList();
            var _UsrDTO = _mapper.Map<UserDTO>(_userd);
            return _UsrDTO;
        }

        public UserResponse CreateProfileUser(UserDTO user, ApiContext apiContext)
        {
            _context = (MICAUMContext)DbManager.GetContext(apiContext.ProductType, apiContext.ServerType);
            var userDetails = user.UserDetails.First();
            var userAddress = user.UserAddress.First();
            EmailTest emailTest = new EmailTest();
            if (string.IsNullOrEmpty(userDetails.UserId))
            {
                var aspNet = _context.AspNetUsers.SingleOrDefault(x => x.UserName == userDetails.Email);
                if (aspNet == null)
                {
                    userDetails.RoleId = null;
                    userDetails.UserName = userDetails.Email;
                    userDetails.CreatedDate = DateTime.Now;
                    //userDetails.ProfileImage = userDetails.ProfileImage;
                    AspNetUsers _users = _mapper.Map<AspNetUsers>(user);
                    if (string.IsNullOrEmpty(_users.Id))
                    {
                        _users.Id = Guid.NewGuid().ToString();
                        _users.UserName = userDetails.Email;
                        _users.Email = userDetails.Email;
                        _users.FirstTimeLogin = 0;
                        _users.PasswordHash = Utilities.GenerateDefaultPassword();
                        emailTest.To = userDetails.Email;
                        emailTest.Subject = "User profile creation";
                        emailTest.Message = "Your account has been created with Username:" + _users.UserName + "\n" + "Please use this for login.";
                        _context.AspNetUsers.Add(_users);
                    }
                    _context.SaveChanges();
                    var _usersDTOs = _mapper.Map<UserDTO>(_users);
                    SendEmailAsync(emailTest);
                    return new UserResponse { Status = BusinessStatus.Created, users = _usersDTOs, Id = _usersDTOs.Id, ResponseMessage = $"User created successfully! \n Login with: {_usersDTOs.Email}" };
                }
                else
                {
                    return new UserResponse { Status = BusinessStatus.Error, ResponseMessage = $"User already exists" };
                }
            }
            else
            {
                AspNetUsers _users = _mapper.Map<AspNetUsers>(user);
                var _useraddress = _mapper.Map<TblUserAddress>(userAddress);
                var _usersDetail = _mapper.Map<TblUserDetails>(userDetails);
                //_context.AspNetUsers.Update(_users);
                //_context.TblUserDetails.Update(_usersDetail);
                _context.Update(_usersDetail);
                _context.Update(_useraddress);
                _context.SaveChanges();
                return new UserResponse { Status = BusinessStatus.Created, users = user, Id = _usersDetail.UserId, ResponseMessage = $"User modified successfully!" };
            }
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
            _context = (MICAUMContext)DbManager.GetContext(apiContext.ProductType, apiContext.ServerType);
            //  var userDetail = user.TblUserDetails.First();
            var _empls = _mapper.Map<TblEmployees>(emp);
            //_empls.Empid = Guid.NewGuid().ToString();
            //DateTime now = DateTime.Now;
            //_users.LockoutEnd = now;
            _context.TblEmployees.Add(_empls);
            _context.SaveChanges();
            var _empDTOs = _mapper.Map<EmployeeDTO>(_empls);
            return _empDTOs;
        }

        public UserDTO ChangeEmailId(UserDTO userDTO, ApiContext apiContext)
        {
            _context = (MICAUMContext)DbManager.GetContext(apiContext.ProductType, apiContext.ServerType);
            AspNetUsers _aspNet = _mapper.Map<AspNetUsers>(userDTO);
            var _aspUsers = _context.AspNetUsers.SingleOrDefault(x => x.Id == _aspNet.Id);

            var _users = _context.TblUserDetails.SingleOrDefault(x => x.UserId == _aspNet.Id);

            _aspUsers.Email = userDTO.Email;
            _users.Email = userDTO.Email;
            _context.AspNetUsers.Update(_aspUsers);
            _context.TblUserDetails.Update(_users);
            _context.SaveChanges();
            var _usersDTOs = _mapper.Map<UserDTO>(_aspUsers);
            return _usersDTOs;
        }

        public UserDTO ChangeMobileNumber(UserDTO userDTO, ApiContext apiContext)
        {
            _context = (MICAUMContext)DbManager.GetContext(apiContext.ProductType, apiContext.ServerType);
            AspNetUsers _aspNet = _mapper.Map<AspNetUsers>(userDTO);
            var _aspUsers = _context.AspNetUsers.SingleOrDefault(x => x.Id == _aspNet.Id);

            var _users = _context.TblUserDetails.SingleOrDefault(x => x.UserId == _aspNet.Id);

            _aspUsers.PhoneNumber = userDTO.PhoneNumber;
            _users.ContactNumber = userDTO.PhoneNumber;
            _context.AspNetUsers.Update(_aspUsers);
            _context.TblUserDetails.Update(_users);
            _context.SaveChanges();
            var _usersDTOs = _mapper.Map<UserDTO>(_aspUsers);
            return _usersDTOs;
        }

        public IEnumerable<UserDetailsDTO> SearchUser(UserSearchDTO searchRequest, ApiContext apiContext)
        {
            _context = (MICAUMContext)DbManager.GetContext(apiContext.ProductType, apiContext.ServerType);
            var _users = _context.TblUserDetails.OrderByDescending(u => u.CreatedDate).Select(x => x);
            if (!string.IsNullOrEmpty(searchRequest.FirstName))
            {
                _users = _users.Where(u => u.FirstName.Contains(searchRequest.FirstName));
            }
            if (!string.IsNullOrEmpty(searchRequest.PanNo))
            {
                _users = _users.Where(u => u.PanNo.Contains(searchRequest.PanNo));
            }
            if (!string.IsNullOrEmpty(searchRequest.EmployeeNumber))
            {
                _users = _users.Where(u => u.EmployeeNumber == searchRequest.EmployeeNumber);
            }
            if (!string.IsNullOrEmpty(searchRequest.EmailId))
            {
                _users = _users.Where(u => u.Email == searchRequest.EmailId);
            }
            if (searchRequest.PartnerId > 0)
            {
                _users = _users.Where(u => u.PartnerId == searchRequest.PartnerId);
            }
            var _usersDTOs = _mapper.Map<List<UserDetailsDTO>>(_users);
            return _usersDTOs;
        }

        public EmployeeDTO SearchEmployee(int Empid, ApiContext apiContext)
        {
            _context = (MICAUMContext)DbManager.GetContext(apiContext.ProductType, apiContext.ServerType);
            var _emp = _context.TblEmployees.SingleOrDefault(x => x.Empid == Empid);
            if (_emp != null)
            {
                TblEmployees _tblUserDetails = _mapper.Map<TblEmployees>(_emp);
                _context.TblEmployees.Find(_emp.Empid);
                var emplDTOs = _mapper.Map<EmployeeDTO>(_emp);
                return emplDTOs;
            }
            else
            {
                return null;
            }
        }

        public UserDTO ModifyUser(UserDTO usersDTOs, ApiContext apiContext)
        {
            _context = (MICAUMContext)DbManager.GetContext(apiContext.ProductType, apiContext.ServerType);
            AspNetUsers _aspNet = _mapper.Map<AspNetUsers>(usersDTOs);
            //We Use .Include Function  to add all Child Classes from a Parent Table 
            //In this Case Parent table is AspNet Users (Primary Key) Child Table is UserDetails (foreign Key)
            // var _aspUsers = _context.AspNetUsers.Include<>.SingleOrDefault(x => x.Id == usersDTOs.Id);
            //var _aspUsers = _context.AspNetUsers.Include<TblUserDetails,>
            //.SingleOrDefault(x => x.Id == usersDTOs.Id);

            //if (_aspUsers != null)
            //{
            //  _aspUsers.PhoneNumber = usersDTOs.PhoneNumber;
            //_aspNet.TblUserDetails.Update();
            _context.AspNetUsers.Update(_aspNet);
            _context.SaveChanges();
            //}
            var _usersDTOs = _mapper.Map<UserDTO>(_aspNet);
            return _usersDTOs;
        }


        //get for master
        public IEnumerable<ddDTO> GetMaster(string lMasterlist, ApiContext apiContext)
        {
            _context = (MICAUMContext)DbManager.GetContext(apiContext.ProductType, apiContext.ServerType);
            IEnumerable<ddDTO> ddDTOs;
            ddDTOs = _context.TblmasUmcommonTypes
             .Select(c => new ddDTO
             {
                 mID = c.CommonTypeId,
                 mValue = c.Value,
                 mType = c.MasterType
             });
            return ddDTOs;
        }

        // get Location
        public IEnumerable<ddDTO> GetLocation(string locationType, int parentID, ApiContext apiContext)
        {
            _context = (MICAUMContext)DbManager.GetContext(apiContext.ProductType, apiContext.ServerType);
            IEnumerable<ddDTO> ddDTOs;

            switch (locationType)
            {
                case "State":
                    ddDTOs = _context.TblMasState.Where(location => location.CountryId == parentID)
                        .Select(c => new ddDTO
                        {
                            mID = c.StateId,
                            mValue = c.StateName,
                            mType = "State"
                        });
                    break;
                case "District":
                    ddDTOs = _context.TblMasDistrict.Where(location => location.StateId == parentID)
                        .Select(c => new ddDTO
                        {
                            mID = c.DistrictId,
                            mValue = c.DistrictName,
                            mType = "District"
                        });
                    break;
                case "City":
                    ddDTOs = _context.TblMasCity.Where(location => location.DistrictId == parentID)
                    .Select(c => new ddDTO
                    {
                        mID = c.CityId,
                        mValue = c.CityName,
                        mType = "City"
                    });
                    break;
                case "Pincode":
                    ddDTOs = _context.TblMasPinCode.Where(location => location.CityId == parentID)
                    .Select(c => new ddDTO
                    {
                        mID = c.PincodeId,
                        mValue = c.Pincode,
                        mType = "Pincode"
                    });
                    break;
                default:
                    ddDTOs = _context.TblMasCountry.Select(location => location)
                    .Select(c => new ddDTO
                    {
                        mID = c.CountryId,
                        mValue = c.CountryName,
                        mType = "Country"
                    });
                    break;
            }
            return ddDTOs;

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
            _context = (MICAUMContext)DbManager.GetContext(apiContext.ProductType, apiContext.ServerType);
            byte[] passwordHash;
            byte[] passwordSalt;
            var _aspUsers = _context.AspNetUsers.FirstOrDefault(x => x.Id == pass.Id);
            if (pass.IsChangePassword == true)
            {
                if (pass.NewPassword == pass.ConfirmPassword)
                {
                    AspNetUsers _aspNet = _mapper.Map<AspNetUsers>(_aspUsers);

                    if (string.IsNullOrWhiteSpace(pass.ConfirmPassword)) throw new ArgumentException("Please enter valid password", "password");

                    passwordSalt = new byte[] { 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20 };
                    using (var hmac = new System.Security.Cryptography.HMACSHA512(passwordSalt))
                    {
                        passwordHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(pass.ConfirmPassword));
                    }
                    _aspNet.PasswordHash = passwordHash;
                    _context.AspNetUsers.Update(_aspNet);
                    _context.SaveChanges();
                    var _usersDTOs = _mapper.Map<UserDTO>(_aspUsers);
                    return new PasswordResponse { Status = BusinessStatus.Created, passwd = pass, ResponseMessage = $"Password changed successfully!" };
                }
                else
                {
                    return new PasswordResponse { Status = BusinessStatus.Error, ResponseMessage = $"Password not matching" };
                }
            }
            else
            {
                if (pass.OldPassword != null)
                {
                    // check if user exists
                    if (_aspUsers == null)
                        return null;

                    passwordSalt = new byte[] { 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20 };

                    //// check if password is correct
                    if (!Utilities.VerifyPasswordHash(pass.OldPassword, _aspUsers.PasswordHash, passwordSalt))
                        return new PasswordResponse { Status = BusinessStatus.UnAuthorized, ResponseMessage = $"Please enter valid old password" };
                    //return null;

                    if (pass.NewPassword == pass.ConfirmPassword)
                    {
                        AspNetUsers _aspNet = _mapper.Map<AspNetUsers>(_aspUsers);
                        if (string.IsNullOrWhiteSpace(pass.ConfirmPassword)) throw new ArgumentException("Please enter valid password", "password");

                        passwordSalt = new byte[] { 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20 };
                        using (var hmac = new System.Security.Cryptography.HMACSHA512(passwordSalt))
                        {
                            passwordHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(pass.ConfirmPassword));
                        }
                        _aspNet.PasswordHash = passwordHash;
                        _context.AspNetUsers.Update(_aspNet);
                        _context.SaveChanges();
                        var _usersDTOs = _mapper.Map<UserDTO>(_aspUsers);
                        return new PasswordResponse { Status = BusinessStatus.Created, passwd = pass, ResponseMessage = $"Password changed successfully!" };
                    }
                    else
                    {
                        return new PasswordResponse { Status = BusinessStatus.InputValidationFailed, passwd = pass, ResponseMessage = $"Password not matching" };
                    }
                }
                else
                {
                    return new PasswordResponse { Status = BusinessStatus.UnAuthorized, ResponseMessage = $"Please enter valid old password" };
                }
            }
        }

        public async Task<SendOtpResponse> SendOTP(SendOtp sendOtp, ApiContext apiContext)
        {
            _context = (MICAUMContext)DbManager.GetContext(apiContext.ProductType, apiContext.ServerType);
            var user = _context.AspNetUsers.SingleOrDefault(x => x.UserName == sendOtp.UserName);
            try
            {
                if (user != null)
                {
                    EmailTest emailTest = new EmailTest();
                    Random random = new Random();
                    int otp = random.Next(100001, 999999);
                    var chkotp = _context.TblSendOtp.Where(a => a.Email == user.Email);
                    if (chkotp != null)
                    {
                        foreach (var item in chkotp)
                        {
                            _context.TblSendOtp.Remove(item);
                        }
                    }
                    sendOtp.UserId = user.Id;
                    sendOtp.Email = user.Email;
                    sendOtp.Otp = otp.ToString();
                    TblSendOtp _otp = _mapper.Map<TblSendOtp>(sendOtp);
                    _context.TblSendOtp.Add(_otp);
                    _context.SaveChanges();
                    emailTest.To = user.Email;
                    emailTest.Subject = "Password reset for MICA";
                    emailTest.Message = "Dear User,\n" + "      " + "\n" + "      OTP for re-setting your MICA password is: " + otp + "      " + "\n" + "\nThanks & Regards:\n" + "      " + "MICA Team";
                    await SendEmailAsync(emailTest);
                }
            }
            catch (Exception ex)
            {
                throw;
            }
            return new SendOtpResponse { Status = BusinessStatus.Ok, sendOtp = sendOtp, ResponseMessage = $"OTP sent successfully!" };
        }

        public async Task<SendOtpResponse> ResetOTP(SendOtp sendOtp, ApiContext apiContext)
        {
            _context = (MICAUMContext)DbManager.GetContext(apiContext.ProductType, apiContext.ServerType);
            var user = _context.AspNetUsers.SingleOrDefault(x => x.Email == sendOtp.Email);
            try
            {
                if (user != null)
                {

                    EmailTest emailTest = new EmailTest();
                    Random random = new Random();
                    int otp = random.Next(1001, 9999);
                    var chkotp = _context.TblSendOtp.Where(a => a.Email == sendOtp.Email);
                    if (chkotp != null)
                    {
                        foreach (var item in chkotp)
                        {
                            _context.TblSendOtp.Remove(item);
                        }
                    }
                    sendOtp.UserId = user.Id;
                    sendOtp.UserName = user.UserName;
                    sendOtp.Otp = otp.ToString();
                    TblSendOtp _otp = _mapper.Map<TblSendOtp>(sendOtp);
                    _context.TblSendOtp.Add(_otp);
                    _context.SaveChanges();
                    emailTest.To = sendOtp.Email;
                    emailTest.Subject = "Password reset for MICA";
                    emailTest.Message = "Dear User,\n" + "      " + "\n" + "      OTP for re-setting your MICA password is: " + otp + "      " + "\n" + "\nThanks & Regards:\n" + "      " + "MICA Team";
                    await SendEmailAsync(emailTest);
                }
                else
                {
                    return new SendOtpResponse { Status = BusinessStatus.NotFound, sendOtp = sendOtp, ResponseMessage = $"Please enter registered Email-ID" };
                }
            }
            catch (Exception ex)
            {

                throw;
            }
            return new SendOtpResponse { Status = BusinessStatus.Ok, sendOtp = sendOtp, ResponseMessage = $"OTP Sent Successfully!" };
        }

        public VerifyOTPResponse VerifyingOTP(VerifyOTP onetp, ApiContext apiContext)
        {
            _context = (MICAUMContext)DbManager.GetContext(apiContext.ProductType, apiContext.ServerType);
            var sentotp = _context.TblSendOtp.SingleOrDefault(x => x.UserId == onetp.UserId);

            if (sentotp.Otp == onetp.Otp)
            {
                var user = _context.AspNetUsers.SingleOrDefault(x => x.Id == sentotp.UserId);
                if (user != null)
                {
                    user.FirstTimeLogin = 1;
                }
                _context.AspNetUsers.Update(user);
                _context.TblSendOtp.Remove(sentotp);
                _context.SaveChanges();
                return new VerifyOTPResponse { Status = BusinessStatus.Ok, ResponseMessage = $"OTP verified successfully!" }; ;
            }
            else
            {
                return new VerifyOTPResponse { Status = BusinessStatus.NotFound, ResponseMessage = $"Invalid OTP" }; ;
            }
        }


        public UserEmailResponse UserEmailValidations(string emailid, ApiContext apiContext)
        {
            _context = (MICAUMContext)DbManager.GetContext(apiContext.ProductType, apiContext.ServerType);
            var email = _context.AspNetUsers.Any(item => item.Email == emailid);
            if (email == true)
            {
                return new UserEmailResponse { Status = BusinessStatus.InputValidationFailed, ResponseMessage = $"Email ID already Exist" };
            }
            else
            {
                return new UserEmailResponse { Status = BusinessStatus.Ok };
            }
        }
        public String DeleteUserById(string Id, ApiContext apiContext)
        {
            _context = (MICAUMContext)DbManager.GetContext(apiContext.ProductType, apiContext.ServerType);
            var tbl_userdata = _context.AspNetUsers.Where(item => item.Id == Id).FirstOrDefault();
            tbl_userdata.IsActive = false;
            _context.SaveChanges();
            return "Deleted!";
        }
    }
}
