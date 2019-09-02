using iNube.Services.UserManagement.Controllers.Permission.PermissionService;
using iNube.Services.UserManagement.Models;
using iNube.Utility.Framework.Model;
using System;
using System.Collections.Generic;

namespace iNube.Services.UserManagement.Controllers.Controllers.Permission.PermissionService.MotorPermission
{
    public class MotorPermissionService : IPermissionProductService
    {
        public UserPermissionResponse AssignPermission(UserPermissionDTO permissionIds, ApiContext apiContext)
        {
            throw new NotImplementedException();
        }

        public IEnumerable<MasPermissionDTO> GetMasPermissions(string perType, ApiContext apiContext)
        {
            throw new NotImplementedException();
        }

        public IEnumerable<MasPermissionDTO> GetPermissions(string perType, string userId, string roleId, ApiContext apiContext)
        {
            throw new NotImplementedException();
        }

        public IEnumerable<MasPermissionDTO> GetRolePermissions(UserRoleMapDTO userPermissionDTO, ApiContext apiContext)
        {
            throw new NotImplementedException();
        }

        public IEnumerable<MasPermissionDTO> GetUserPermissions(string perType, string userId, ApiContext apiContext)
        {
            throw new NotImplementedException();
        }

        public UserPermissionResponse SaveAssignPermission(UserRolesPermissionDTO permissionIds, ApiContext apiContext)
        {
            throw new NotImplementedException();
        }

        public NewRolePermissionResponse AssignRolePermission(NewRolesPermissionDTO permissionIds, ApiContext apiContext)
        {
            throw new NotImplementedException();
        }
    }
}
