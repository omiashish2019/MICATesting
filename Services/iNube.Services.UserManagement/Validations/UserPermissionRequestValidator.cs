using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using FluentValidation;
using iNube.Services.UserManagement.Models;
using iNube.Utility.Framework.Helpers.Business.Validations;

namespace iNube.Services.UserManagement.Validations
{
    public class UserPermissionRequestValidator : BaseValidator<UserPermissionDTO>
    {
        protected override void RuleFor()
        {
            RuleForEach(user => user.UserId)
                 .NotNull()
               .WithMessage("User Id is required")
               .WithErrorCode("UserId_required");

            RuleFor(request => request.PermissionIds)
                .NotEmpty()
               .WithMessage("Permission Ids is required")
               .WithErrorCode("PermissionIds_required");
        }
    }
}
