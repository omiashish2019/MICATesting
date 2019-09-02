using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using FluentValidation;
using iNube.Services.UserManagement.Models;
using iNube.Utility.Framework.Helpers.Business.Validations;

namespace iNube.Services.UserManagement.Validations
{
    public class AssignRoleRequestValidator : BaseValidator<UserRoleMapDTO>
    {
        /// <summary>
        /// Derived method from virtual method base for Rules implementation
        /// </summary>
        protected override void RuleFor()
        {
            RuleForEach(user => user.RoleId)
                 .NotNull()
               .WithMessage("Role Id is required")
               .WithErrorCode("RoleId_required");

            RuleFor(request => request.UserId)
                .NotEmpty()
               .WithMessage("UserId is required")
               .WithErrorCode("UserId_required");
        }
    }
}
