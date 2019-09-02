using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using AutoMapper;
using iNube.Services.UserManagement.Controllers.Permission.PermissionService;
using iNube.Services.UserManagement.Helpers;
using iNube.Services.UserManagement.Models;
using iNube.Utility.Framework;
using iNube.Utility.Framework.Model;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;

namespace iNube.Services.UserManagement.Controllers.Permission
{
    [Route("api/[controller]/[action]")]
    [ApiController]
    [Authorize(AuthenticationSchemes = "Bearer")]
    //[Authorize]
    public class PermissionController : BaseApiController
    {
        public IPermissionService _permissionService;
        private IMapper _mapper;
        private readonly AppSettings _appSettings;

        public PermissionController(
          IPermissionService permissionService,
            IMapper mapper,
            IOptions<AppSettings> appSettings)
        {
            _permissionService = permissionService;
            _mapper = mapper;
            _appSettings = appSettings.Value;
        }

        //GET: api/Permission/GetMasPermissions
        [HttpGet]
        public IActionResult GetMasPermissions(string permissionType)
        {
            if (permissionType == null)
            {
                return NoContent();
            }
            else
            {
                var _permissions = _permissionService.GetMasPermissions(permissionType, Context);
                return Ok(_permissions);
            }
        }
        //GET: api/Permission/GetUserPermissions
        [HttpGet]
        public IActionResult GetUserPermissions(string permissionType, string userId)
        {
            if (permissionType == null || userId == null)
            {
                return NoContent();
            }
            else
            {
                var _permissions = _permissionService.GetUserPermissions(permissionType, userId, Context);
                return Ok(_permissions);
            }
        }

        //GET: api/Permission/GetPermissions
        [HttpGet]
        public IActionResult GetPermissions(string permissionType, string userId, string roleId)
        {
            if (permissionType == null || userId == null || roleId == null)
            {
                return NoContent();
            }
            else
            {
                var _permissions = _permissionService.GetPermissions(permissionType, userId, roleId, Context);
                return Ok(_permissions);
            }
        }
        [HttpGet]
        public IActionResult GetProductPermissions(string permissionType, string userId, string roleId,string productType)
        {
            if (permissionType == null || userId == null || roleId == null)
            {
                return NoContent();
            }
            else
            {
                var _permissions = _permissionService.GetUserPermissions(permissionType, userId, Context);
                return Ok(_permissions);
            }
        }

        //POST : api/Permission/AssignPermission
        [HttpPost]
        public IActionResult AssignPermission([FromBody] UserPermissionDTO PermissionIds)
        {
            var response = _permissionService.AssignPermission(PermissionIds, Context);
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

        [HttpPost]
        public IActionResult GetRolePermissions(UserRoleMapDTO userPermissionDTO)
        {
            var _permissions = _permissionService.GetRolePermissions(userPermissionDTO, Context);
            var masterdata = _permissions.GroupBy(c => new { c.RoleName }).Select(mdata => new { mdata.Key.RoleName, mdata });
            return Ok(masterdata);

        }
        [HttpPost]
        public IActionResult SaveRolePermissions(UserRolesPermissionDTO userPermissionDTO)
        {
            var response = _permissionService.SaveAssignPermission(userPermissionDTO, Context);
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

        [HttpPost]
        public IActionResult AssignRolePermissions(NewRolesPermissionDTO newRolePermissionDTO)
        {
            var response = _permissionService.AssignRolePermission(newRolePermissionDTO, Context);
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
    }
}
