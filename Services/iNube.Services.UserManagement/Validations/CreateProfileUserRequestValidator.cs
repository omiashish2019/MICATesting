using FluentValidation;
using FluentValidation.Validators;
using iNube.Services.UserManagement.Models;
using iNube.Utility.Framework.Helpers.Business.Validations;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace iNube.Services.UserManagement.Validations
{
    public class CreateProfileUserRequestValidator : BaseValidator<UserDTO>
    {
        /// <summary>
        /// Derived method from virtual method base for Rules implementation
        /// </summary>
        protected override void RuleFor()
        {
            RuleFor(request => request.UserDetails)
                   .NotNull()
                   .WithMessage("User detail is required")
                   .WithErrorCode("UserDetail_required");

            RuleForEach(user => user.UserDetails).SetValidator(new UserDetailValidator());
            RuleForEach(user => user.UserAddress).SetValidator(new UserAddressValidator());
        }
    }
    public class UserDetailValidator : BaseValidator<UserDetailsDTO>
    {
        /// <summary>
        /// Derived method from virtual method base for Rules implementation
        /// </summary>
        protected override void RuleFor()
        {

            RuleFor(request => request.UserTypeId)
               .NotEmpty()
               .WithMessage("UserType is required")
               .WithErrorCode("UserType_required");

            RuleFor(request => request.FirstName)
               .NotEmpty()
               .WithMessage("FirstName is required")
               .WithErrorCode("FirstName_required");

            RuleFor(request => request.MaritalStatusId)
               .NotEmpty()
               .WithMessage("MaritalStatus is required")
               .WithErrorCode("MaritalStatusId_required");

            RuleFor(request => request.Dob)
               .NotEmpty()
               .WithMessage("Date of Birth is required")
               .WithErrorCode("DateofBirth_required");

            RuleFor(request => request.Doj)
               .NotEmpty()
               .WithMessage("Date of Joining is required")
               .WithErrorCode("DateofJoining_required");

            RuleFor(request => request.GenderId)
               .NotEmpty()
               .WithMessage("Gender is required")
               .WithErrorCode("Gender_required");

            RuleFor(request => request.ContactNumber)
               .NotEmpty()
               .WithMessage("Mobile Number is required")
               .WithErrorCode("MobileNumber_required");

            RuleFor(request => request.PanNo)
               .NotEmpty()
               .WithMessage("Pan Number is required")
               .WithErrorCode("PanNumber_required");


            RuleFor(request => request.Email)
               .NotEmpty()
               .WithMessage("Email is required")
               .WithErrorCode("Email_required");

            
        }
    }

    public class UserAddressValidator : BaseValidator<UserAddressDTO>
    {
        protected override void RuleFor()
        {
            RuleFor(request => request.UserAddressLine1)
               .NotEmpty()
               .WithMessage("AddressLine1 is required")
               .WithErrorCode("AddressLine1_required");

            RuleFor(request => request.UserCountryId)
               .NotEmpty()
               .WithMessage("Country is required")
               .WithErrorCode("Country_required");

            RuleFor(request => request.UserStateId)
               .NotEmpty()
               .WithMessage("State is required")
               .WithErrorCode("State_required");

            RuleFor(request => request.UserDistrictId)
               .NotEmpty()
               .WithMessage("District is required")
               .WithErrorCode("District_required");

            RuleFor(request => request.UserCityId)
               .NotEmpty()
               .WithMessage("City is required")
               .WithErrorCode("City_required");
        }
    }
}

