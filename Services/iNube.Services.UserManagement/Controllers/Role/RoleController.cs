using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using AutoMapper;
using iNube.Services.UserManagement.Controllers.Role.RoleService;
using iNube.Services.UserManagement.Helpers;
using iNube.Services.UserManagement.Models;
using iNube.Utility.Framework;
using iNube.Utility.Framework.Model;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;

namespace iNube.Services.UserManagement.Controllers.Role
{
    [Route("api/[controller]/[action]")]
    [ApiController]
    [Authorize(AuthenticationSchemes = "Bearer")]
    public class RoleController : BaseApiController
    {
        public IRoleService _roleService;
        private IMapper _mapper;
        private readonly AppSettings _appSettings;

        public RoleController(
          IRoleService roleService,
            IMapper mapper,
            IOptions<AppSettings> appSettings)
        {
            _roleService = roleService;
            _mapper = mapper;
            _appSettings = appSettings.Value;
        }

        // Get: api/Role/GetRoles
        [HttpGet]
        public IActionResult GetRoles()
        {
            var _roles = _roleService.GetRoles(Context);
            return Ok(_roles);
        }

        // POST: api/Role/AssignRole
        [HttpPost]
        public IActionResult AssignRole([FromBody] UserRoleMapDTO userRoles)
        {
            var usrrole = _roleService.AssignRole(userRoles, Context);
            return ServiceResponse(usrrole);
            //switch (usrrole.Status)
            //{
            //    case BusinessStatus.InputValidationFailed:
            //        return Ok(usrrole);
            //    case BusinessStatus.Created:
            //        return Ok(usrrole);
            //    case BusinessStatus.UnAuthorized:
            //        return Unauthorized();
            //    default:
            //        return Forbid();
            //}
        }

        // PUT: api/Role/ModifyRole
        [HttpPut("{id}")]
        public void ModifyRole(int id, [FromBody] string value)
        {
        }

        // Post: api/Role/CreateRole
        [HttpPost]
        public IActionResult CreateRole([FromBody] RolesDTO role)
        {
            var response = _roleService.CreateRole(role, Context);
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

        // DELETE: api/Role/DeleteRole
        [HttpDelete("{id}")]
        public void DeleteRole(int id)
        {
        }

        [HttpGet("{userId}")]
        public IActionResult GetUserRole(string userId)
        {
            var _roles = _roleService.GetUserRole(userId, Context);
            return Ok(_roles);
        }
    }
}
