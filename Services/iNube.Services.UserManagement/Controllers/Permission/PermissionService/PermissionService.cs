using AutoMapper;
using iNube.Services.UserManagement.Entities;
using iNube.Services.UserManagement.Models;
using iNube.Utility.Framework.Model;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Linq;
using iNube.Services.UserManagement.Helpers;

namespace iNube.Services.UserManagement.Controllers.Permission.PermissionService
{
    public interface IPermissionService
    {
        IEnumerable<MasPermissionDTO> GetMasPermissions(string perType, ApiContext apiContext);
        IEnumerable<MasPermissionDTO> GetUserPermissions(string perType, string userId, ApiContext apiContext);
        IEnumerable<MasPermissionDTO> GetPermissions(string perType, string userId, string roleId, ApiContext apiContext);
        UserPermissionResponse AssignPermission(UserPermissionDTO permissionIds, ApiContext apiContext);
        IEnumerable<MasPermissionDTO> GetRolePermissions(UserRoleMapDTO userPermissionDTO, ApiContext apiContext);
        UserPermissionResponse SaveAssignPermission(UserRolesPermissionDTO permissionIds, ApiContext apiContext);
        NewRolePermissionResponse AssignRolePermission(NewRolesPermissionDTO permissionIds, ApiContext apiContext);
    }

    public class PermissionService : IPermissionService
    {
        private MICAUMContext _context;
        private IMapper _mapper;
        private readonly Func<string, IPermissionProductService> _permissionService;
        public PermissionService(IMapper mapper, Func<string, IPermissionProductService> permissionService)
        {
            _mapper = mapper;
            _permissionService = permissionService;
        }

        public IEnumerable<MasPermissionDTO> GetMasPermissions(string perType, ApiContext apiContext)
        {
            return _permissionService(apiContext.ProductType).GetMasPermissions(perType, apiContext);
        }

        public IEnumerable<MasPermissionDTO> GetUserPermissions(string perType, string userId, ApiContext apiContext)
        {
            return _permissionService(apiContext.ProductType).GetUserPermissions(perType,userId, apiContext);
        }

        public IEnumerable<MasPermissionDTO> GetPermissions(string perType, string userId, string roleId, ApiContext apiContext)
        {
            return _permissionService(apiContext.ProductType).GetPermissions(perType, userId,roleId, apiContext);
        }

        private IEnumerable<MasPermissionDTO> GetChildren(IEnumerable<TblMasPermission> permissions, int parentId)
        {
            IEnumerable<MasPermissionDTO> masPermissionDTOs = permissions
                    .Where(c => c.ParentId == parentId)
                    .Select(c => new MasPermissionDTO
                    {
                        PermissionId = c.PermissionId,
                        ItemType = c.ItemType,
                        ParentId = c.ParentId,
                        MenuId = c.MenuId,
                        ItemDescription = c.ItemDescription,
                        Label=c.ItemDescription,
                        Url = c.Url,
                        PathTo = c.PathTo,
                        Collapse = c.Collapse,
                        State = c.State,
                        Mini = c.Mini,
                        Icon = c.Icon,
                        Redirect = c.Redirect,
                        Component = c.Component,
                        Children = GetChildren(permissions, c.PermissionId)
                    });
            return masPermissionDTOs;
        }


        public UserPermissionResponse AssignPermission(UserPermissionDTO permissionIds, ApiContext apiContext)
        {
            return _permissionService(apiContext.ProductType).AssignPermission(permissionIds, apiContext);
        }
        public UserPermissionResponse SaveAssignPermission(UserRolesPermissionDTO permissionIds, ApiContext apiContext)
        {
            return _permissionService(apiContext.ProductType).SaveAssignPermission(permissionIds, apiContext);
        }
        public NewRolePermissionResponse AssignRolePermission(NewRolesPermissionDTO permissionIds, ApiContext apiContext)
        {
            return _permissionService(apiContext.ProductType).AssignRolePermission(permissionIds, apiContext);
        }


        public IEnumerable<MasPermissionDTO> GetUserRolePermissions(UserRoleMapDTO userPermissionDTO, ApiContext apiContext)
        {
            _context = (MICAUMContext)DbManager.GetContext(apiContext.ProductType, apiContext.ServerType);
            var ruleNames = _context.AspNetRoles.Where(r => userPermissionDTO.RoleId.Contains(r.Id)).ToList();
            var menuPermission = (from permission in _context.TblUserPermissions
                               join c in _context.TblMasPermission on permission.PermissionId equals c.PermissionId
                               where userPermissionDTO.RoleId.Contains(permission.RoleId)
                                && permission.UserorRole == "Role"
                               select new MasPermissionDTO
                               {
                                   PermissionId = c.PermissionId,
                                   ItemType = c.ItemType,
                                   ParentId = c.ParentId,
                                   MenuId = c.MenuId,
                                   ItemDescription = c.ItemDescription,
                                   Label = c.ItemDescription,
                                   Url = c.Url,
                                   PathTo = c.PathTo,
                                   Collapse = c.Collapse,
                                   State = c.State,
                                   Mini = c.Mini,
                                   Icon = c.Icon,
                                   Redirect = c.Redirect,
                                   Component = c.Component,
                                   Status = true,
                                   RoleId=permission.RoleId,
                                   RoleName = ruleNames.First(r => r.Id == permission.RoleId).Name
                               }).ToList();

            var userPermissions = from c in _context.TblMasPermission
                                  join permission in _context.TblUserPermissions on c.PermissionId equals permission.PermissionId
                                  where permission.UserId == userPermissionDTO.UserId
                                  && permission.UserorRole == "User"
                                  select permission;

            if (userPermissions.Any())
            {
                foreach (var item in userPermissions)
                {
                    var mPermission = menuPermission.FirstOrDefault(m => m.PermissionId == item.PermissionId && m.RoleId==item.RoleId);
                    if (mPermission != null)
                    {
                        mPermission.Status = false;
                    }
                }
            }
            IEnumerable<MasPermissionDTO> _masPermissionDTOs = menuPermission
                           .Where(c => (c.ParentId == 0))
                           .Select(c => new MasPermissionDTO()
                           {
                               PermissionId = c.PermissionId,
                               ItemType = c.ItemType,
                               ParentId = c.ParentId,
                               MenuId = c.MenuId,
                               ItemDescription = c.ItemDescription,
                               Label = c.ItemDescription,
                               Url = c.Url,
                               PathTo = c.PathTo,
                               Collapse = c.Collapse,
                               State = c.State,
                               Mini = c.Mini,
                               Icon = c.Icon,
                               Redirect = c.Redirect,
                               Component = c.Component,
                               Status=c.Status,
                               RoleId=c.RoleId,
                               RoleName=c.RoleName,
                               Children = GetMenuChildren(menuPermission, c.PermissionId,c.RoleId)
                           });
            return _masPermissionDTOs;
        }
        private IEnumerable<MasPermissionDTO> GetMenuChildren(IEnumerable<MasPermissionDTO> permissions, int parentId,string roleId)
        {
            IEnumerable<MasPermissionDTO> masPermissionDTOs = permissions
                    .Where(c => c.ParentId == parentId && c.RoleId== roleId)
                    .Select(c => new MasPermissionDTO
                    {
                        PermissionId = c.PermissionId,
                        ItemType = c.ItemType,
                        ParentId = c.ParentId,
                        MenuId = c.MenuId,
                        ItemDescription = c.ItemDescription,
                        Label = c.ItemDescription,
                        Url = c.Url,
                        PathTo = c.PathTo,
                        Collapse = c.Collapse,
                        State = c.State,
                        Mini = c.Mini,
                        Icon = c.Icon,
                        Redirect = c.Redirect,
                        Component = c.Component,
                        RoleId=c.RoleId,
                        RoleName = c.RoleName,
                        Status =c.Status,
                        Children = GetMenuChildren(permissions, c.PermissionId,c.RoleId)
                    });
            return masPermissionDTOs;
        }
        public IEnumerable<MasPermissionDTO> GetRolePermissions(UserRoleMapDTO userPermissionDTO, ApiContext apiContext)
        {
            return GetUserRolePermissions(userPermissionDTO, apiContext);
        }
    }
}
