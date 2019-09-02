using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using AutoMapper;
using iNube.Services.UserManagement.Controllers.UserProfile.UserProfileService;
using iNube.Services.UserManagement.Entities;
using iNube.Services.UserManagement.Helpers;
using iNube.Services.UserManagement.Models;
using iNube.Utility.Framework;
using iNube.Utility.Framework.Model;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;

namespace iNube.Services.UserManagement.Controllers.UserProfile
{
    [Route("api/[controller]/[action]")]
    [ApiController]
    [Authorize(AuthenticationSchemes = "Bearer")]
    public class UserProfileController : BaseApiController
    {
        public IUserProfileService _userService;
        private IMapper _mapper;
        private readonly AppSettings _appSettings;

        public UserProfileController(
          IUserProfileService userService,
            IMapper mapper,
            IOptions<AppSettings> appSettings)
        {
            _userService = userService;
            _mapper = mapper;
            _appSettings = appSettings.Value;
        }

        // GET: api/UserProfile/GetUserByUserId
        [HttpGet]
        public IActionResult GetUserByUserId(string Id)
        {
            TblUserDetails _user  = _userService.GetUserByUserId(Id,Context);
            return Ok(_user);

        }

        // GET: api/UserProfile/SearchUserById
        [HttpGet]
        public IActionResult SearchUserById(string Id)
        {
            var _user = _userService.SearchUserById(Id, Context);
            return Ok(_user);

        }


        // POST: api/UserProfile/CreateProfileUser
        [HttpPost]
        public IActionResult CreateProfileUser([FromBody] UserDTO usersDTOs)
        {
            var response = _userService.CreateProfileUser(usersDTOs, Context);
            return ServiceResponse(response);
            //switch (response.Status)
            //{
            //    case BusinessStatus.InputValidationFailed:
            //        return Ok(response);
            //    case BusinessStatus.Created:
            //        return Ok(response);
            //    case BusinessStatus.UnAuthorized:
            //        return Unauthorized();
            //    default:
            //        return Forbid();
            //}
        }

        // POST: api/UserProfile/CreateProfileemployee
        //[HttpPost]
        // public IActionResult CreateProfileemployee([FromBody] EmployeeDTO emplDTOs)
        // {
        //     save

        //    var empl = _userService.CreateProfileemployee(emplDTOs,Context);
        //     return Ok(empl.Empid);


        // }

        // POST: api/UserProfile/ChangeEmailId
        [HttpPost]
        public IActionResult ChangeEmailId(string UserId,string Email)
        {
            try
            {
                 UserDTO userDTO = new UserDTO();
                 userDTO.Id = UserId;
                 userDTO.Email = Email;
                // save 
                _userService.ChangeEmailId(userDTO, Context);
                return Ok();
            }
            catch (AppException ex)
            {

            }
            return Ok();

           
        }

        // POST: api/UserProfile/ChangeMobileNumber
        [HttpPost]
        public IActionResult ChangeMobileNumber(string UserId, string MobileNumber)
        {

            try
            {
                UserDTO userDTO = new UserDTO();
                userDTO.Id = UserId;
                userDTO.PhoneNumber = MobileNumber;
                // save 
                _userService.ChangeMobileNumber(userDTO, Context);
                return Ok();
            }
            catch (AppException ex)
            {

            }
            return Ok();

        }

        [HttpPost]
        public IActionResult SearchUser(UserSearchDTO searchRequest)
        {
            var search = _userService.SearchUser(searchRequest, Context);
            return Ok(search);

        }



        // GET: api/UserProfile/employeesearch
        [HttpGet]
        public IActionResult Employee(int Empid)
        {
                EmployeeDTO search = _userService.SearchEmployee(Empid, Context);

                return Ok(search);
           
        }


        // POST: api/UserProfile/GeneratePassword
        [HttpPost]
        public string GeneratePassword([FromBody] string password)
        {
            //converts string data to byte
            //To get data as byte array you could use
            //var data = Encoding.ASCII.GetBytes(password);


            // get back string from md5data or sha1data
            //var hashedPassword = ASCIIEncoding.GetString(md5data);

            // MD5Crypto to generate hash password
            //var md5 = new MD5CryptoServiceProvider();
            //var md5data = md5.ComputeHash(data);

            //SHA1 hash algorithm
            //var sha1 = new SHA1CryptoServiceProvider();
            //var sha1data = sha1.ComputeHash(data);


            return "True";
        }

        // PUT: api/UserProfile/ModifyUser
        [HttpPut("{UserId}")]
        public IActionResult ModifyUser(string UserId, [FromBody] UserDTO usersDTOs)
        {
            usersDTOs.Id = UserId;
            _userService.ModifyUser(usersDTOs, Context);
            return Ok();

        }

        // DELETE: api/UserProfile/DeleteUser
        [HttpDelete]
        public string DeleteUser([FromBody] string value)
        {
            return "True";
        }

        // GET: api/Product/GetMasterData
        [HttpGet]
        public IActionResult GetMasterData(string sMasterlist)
        {
            var commonTypesDTOs = _userService.GetMaster(sMasterlist, Context);
            var masterdata = commonTypesDTOs.GroupBy(c => new { c.mType }).Select(mdata => new { mdata.Key.mType, mdata, });
            return Ok(masterdata);
        }

        // GET: api/Product/GetLocation
        [HttpGet]
        public IActionResult GetLocation(string locationType, int parentID)
        {
            var locationData = _userService.GetLocation(locationType, parentID, Context);
            return Ok(locationData);
        }
        [HttpPost]
        public async Task<IActionResult> SendEmailAsync(EmailTest emailTest)
        {
            var emailData = await _userService.SendEmailAsync(emailTest);
            return Ok(emailData);
        }

        // Post: api/UserProfile/ChangePassword
        [HttpPost]
        [AllowAnonymous]
        public IActionResult ChangePassword(Password pass)
        {
            var response = _userService.ChangePassword(pass, Context);
            return ServiceResponse(response);
            //switch (response.Status)
            //{
            //    case BusinessStatus.InputValidationFailed:
            //        return Ok(response);
            //    case BusinessStatus.Created:
            //        return Ok(response);
            //    case BusinessStatus.UnAuthorized:
            //        return Unauthorized();
            //    default:
            //        return Forbid();
            //}

            //return Ok(_password);

        }

        [HttpPost]
        [AllowAnonymous]
        public async Task<IActionResult> SendOTP(SendOtp sendOtp)
        {
            var OtpData = await _userService.SendOTP(sendOtp, Context);
            return Ok(OtpData);
        }

        [HttpPost]
        [AllowAnonymous]
        public async Task<IActionResult> ResetOTP(SendOtp sendOtp)
        {
            var response = await _userService.ResetOTP(sendOtp, Context);
            return ServiceResponse(response);
            //switch (response.Status)
            //{
            //    case BusinessStatus.NotFound:
            //        return Ok(response);
            //    case BusinessStatus.Ok:
            //        return Ok(response);
            //    default:
            //        return Forbid();
            //}
            //return Ok(OtpData);
        }

        [HttpPost]
        [AllowAnonymous]
        public IActionResult VerifyingOTP(VerifyOTP verifyOTP)
        {
            var response =  _userService.VerifyingOTP(verifyOTP, Context);
            return ServiceResponse(response);
            //switch (response.Status)
            //{
            //    case BusinessStatus.NotFound:
            //        return Ok(response);
            //    case BusinessStatus.Ok:
            //        return Ok(response);
            //    default:
            //        return Forbid();
            //}
        }



        [HttpGet]
        [AllowAnonymous]
        public IActionResult UserEmailValidation(string searchRequest)
        {
            var response = _userService.UserEmailValidations(searchRequest, Context);
            return ServiceResponse(response);
            //switch (response.Status)
            //{
            //    case BusinessStatus.InputValidationFailed:
            //        return Ok(response);
                
            //    case BusinessStatus.Ok:
            //        return Ok(response);
            //    default:
            //        return Forbid();
            //}

        }
        [HttpGet]
        public string DeleteUserById(string Id)
        {
            var response = _userService.DeleteUserById(Id, Context);
            return response;

        }
       
    }
}