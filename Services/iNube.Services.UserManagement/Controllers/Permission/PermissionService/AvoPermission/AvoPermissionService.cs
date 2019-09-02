using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using AutoMapper;
using iNube.Services.UserManagement.Controllers.Permission.PermissionService;
using iNube.Services.UserManagement.Entities.AVO;
using iNube.Services.UserManagement.Helpers;
using iNube.Services.UserManagement.Models;
using iNube.Utility.Framework.Model;
using iNube.Utility.Framework.Notification;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace iNube.Services.UserManagement.Controllers.Controllers.Permission.PermissionService.MicaPermission
{
    /// <summary>
    /// 
    /// </summary>
    /// <seealso cref="iNube.Services.UserManagement.Controllers.Permission.PermissionService.IPermissionProductService" />
    public class AvoPermissionService : IPermissionProductService
    {
        private AVOUMContext _context;
        private IMapper _mapper;

        /// <summary>
        /// Initializes a new instance of the <see cref="AvoPermissionService"/> class.
        /// </summary>
        /// <param name="mapper">The mapper.</param>
        public AvoPermissionService( IMapper mapper)
        {
            _mapper = mapper;
        }

        #region Public Methods        
        /// <summary>
        /// Gets the mas permissions.
        /// </summary>
        /// <param name="perType">Type of the per.</param>
        /// <param name="apiContext">The API context.</param>
        /// <returns></returns>
        public IEnumerable<MasPermissionDTO> GetMasPermissions(string perType, ApiContext apiContext)
        {
            _context = (AVOUMContext)DbManager.GetContext(apiContext.ProductType, apiContext.ServerType);
            IEnumerable<TblMasPermission> _permissions = _context.TblMasPermission.Where(per => per.ItemType == perType);
            IEnumerable<MasPermissionDTO> _masPermissionDTOs = _mapper.Map<IEnumerable<MasPermissionDTO>>(_permissions);
            return _masPermissionDTOs;
        }
        /// <summary>
        /// Gets the user permissions.
        /// </summary>
        /// <param name="perType">Type of the per.</param>
        /// <param name="userId">The user identifier.</param>
        /// <param name="apiContext">The API context.</param>
        /// <returns></returns>
        public IEnumerable<MasPermissionDTO> GetUserPermissions(string perType, string userId, ApiContext apiContext)
        {
            _context = (AVOUMContext)DbManager.GetContext(apiContext.ProductType, apiContext.ServerType);
            var _roles = _context.AspNetUserRoles.Where(userrole => userrole.UserId == userId).Select(role => role.RoleId);

            IEnumerable<TblMasPermission> _permissions = from maspermission in _context.TblMasPermission
                                                         join permission in
                                                            (from rolepermission in _context.TblUserPermissions
                                                             where _roles.Contains(rolepermission.RoleId)
                                                             && rolepermission.UserorRole == "Role"
                                                             select rolepermission.PermissionId)
                                                                .Except(
                                                                        from userpermission in _context.TblUserPermissions
                                                                        where userpermission.UserId == userId
                                                                        && userpermission.UserorRole == "User"
                                                                        select userpermission.PermissionId
                                                                        ) on maspermission.PermissionId equals permission.Value
                                                         where maspermission.ItemType == perType
                                                         select maspermission;

            IEnumerable<MasPermissionDTO> _masPermissionDTOs = _mapper.Map<IEnumerable<MasPermissionDTO>>(_permissions);
            return _masPermissionDTOs;
        }
        /// <summary>
        /// Gets the permissions.
        /// </summary>
        /// <param name="perType">Type of the per.</param>
        /// <param name="userId">The user identifier.</param>
        /// <param name="roleId">The role identifier.</param>
        /// <param name="apiContext">The API context.</param>
        /// <returns></returns>
        public IEnumerable<MasPermissionDTO> GetPermissions(string perType, string userId, string roleId, ApiContext apiContext)
        {
            _context = (AVOUMContext)DbManager.GetContext(apiContext.ProductType, apiContext.ServerType);
            IEnumerable<TblMasPermission> _permissions = from maspermission in _context.TblMasPermission
                                                         join permission in
                                                            (from rolepermission in _context.TblUserPermissions
                                                             where rolepermission.RoleId == roleId
                                                             && rolepermission.UserorRole == "Role"
                                                             select rolepermission.PermissionId)
                                                                .Except(
                                                                        from userpermission in _context.TblUserPermissions

                                                                        where userpermission.UserId == userId
                                                                        && userpermission.UserorRole == "User"
                                                                        select userpermission.PermissionId
                                                                        ) on maspermission.PermissionId equals permission.Value
                                                         where maspermission.ItemType == perType
                                                         orderby maspermission.SortOrderBy ascending
                                                         select maspermission;

            IEnumerable<MasPermissionDTO> _masPermissionDTOs = _permissions
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
                                Children = GetChildren(_permissions, c.PermissionId)
                            });
            // 
            return _masPermissionDTOs;
        }


        /// <summary>
        /// Assigns the permission.
        /// </summary>
        /// <param name="permissionIds">The permission ids.</param>
        /// <param name="apiContext">The API context.</param>
        /// <returns></returns>
        public UserPermissionResponse AssignPermission(UserPermissionDTO permissionIds, ApiContext apiContext)
        {
            _context = (AVOUMContext)DbManager.GetContext(apiContext.ProductType, apiContext.ServerType);
            UserPermissionsDTO userPermissions = null;
            for (int i = 0; i < permissionIds.PermissionIds.Length; i++)
            {
                userPermissions = new UserPermissionsDTO();
                userPermissions.UserId = permissionIds.UserId;
                userPermissions.PermissionId = Convert.ToInt16(permissionIds.PermissionIds[i]);
                userPermissions.UserorRole = "User";
                // userPermissions.CreatedBy = CreatedBy;
                userPermissions.CreatedDate = DateTime.Now;
                userPermissions.Status = true;
                var _usersPer = _mapper.Map<TblUserPermissions>(userPermissions);
                _context.TblUserPermissions.Add(_usersPer);
            }
            _context.SaveChanges();
            //return userPermissions;
            return new UserPermissionResponse { Status = BusinessStatus.Created, perm = userPermissions, ResponseMessage = $"Assigned {userPermissions.PermissionId} Permissions successfully!!" };

        }

        /// <summary>
        /// Saves the assign permission.
        /// </summary>
        /// <param name="permissionIds">The permission ids.</param>
        /// <param name="apiContext">The API context.</param>
        /// <returns></returns>
        public UserPermissionResponse SaveAssignPermission(UserRolesPermissionDTO permissionIds, ApiContext apiContext)
        {
            _context = (AVOUMContext)DbManager.GetContext(apiContext.ProductType, apiContext.ServerType);
            TblUserPermissions userPermissions = null;
            foreach (var item in permissionIds.RolePermissionIds)
            {
                var newPermission = item.PermissionIds.ToList();
                var existingPerm = _context.TblUserPermissions.Where(t => t.UserId == permissionIds.UserId && t.UserorRole == "User" && t.RoleId == item.RoleId).ToList();
                //Delete which are not in current permissions--
                var delPermission = existingPerm.Where(m => !item.PermissionIds.Contains((int)m.PermissionId)).ToList();
                foreach (var perm in delPermission)
                {
                    _context.Remove(perm);
                    existingPerm.Remove(perm);
                }
                var includedPermission = existingPerm.Where(m => item.PermissionIds.Contains((int)m.PermissionId)).ToList();
                foreach (var incPerm in includedPermission)
                {
                    newPermission.Remove((int)incPerm.PermissionId);
                }
                //Add new record
                foreach (var permissionId in newPermission)
                {
                    userPermissions = new TblUserPermissions();
                    userPermissions.UserId = permissionIds.UserId;
                    userPermissions.PermissionId = permissionId;
                    userPermissions.RoleId = item.RoleId;
                    userPermissions.UserorRole = "User";
                    // userPermissions.CreatedBy = CreatedBy;
                    userPermissions.CreatedDate = DateTime.Now;
                    userPermissions.Status = true;
                    _context.TblUserPermissions.Add(userPermissions);
                }

            }

            _context.SaveChanges();
            return new UserPermissionResponse { Status = BusinessStatus.Created, Id = userPermissions?.UserPermissionsId.ToString(), ResponseMessage = $"Assigned Permissions successfully!!" };

        }

        public NewRolePermissionResponse AssignRolePermission(NewRolesPermissionDTO permissionIds, ApiContext apiContext)
        {
            _context = (AVOUMContext)DbManager.GetContext(apiContext.ProductType, apiContext.ServerType);
            TblUserPermissions userPermissions = null;
            //foreach (var item in permissionIds.RolePermissionIds)
            //{
            //    var newPermission = item.PermissionIds.ToList();
            //    var existingPerm = _context.TblUserPermissions.Where(t => t.RoleId == permissionIds.RoleId && t.UserorRole == "Role" && t.RoleId == item.RoleId).ToList();
            //    //Delete which are not in current permissions--
            //    var delPermission = existingPerm.Where(m => !item.PermissionIds.Contains((int)m.PermissionId)).ToList();
            //    foreach (var perm in delPermission)
            //    {
            //        _context.Remove(perm);
            //        existingPerm.Remove(perm);
            //    }
            //    var includedPermission = existingPerm.Where(m => item.PermissionIds.Contains((int)m.PermissionId)).ToList();
            //    foreach (var incPerm in includedPermission)
            //    {
            //        newPermission.Remove((int)incPerm.PermissionId);
            //    }
                //Add new record
                foreach (var permissionId in permissionIds.PermissionIds)
                {
                    userPermissions = new TblUserPermissions();
                    userPermissions.PermissionId = permissionId;
                    userPermissions.RoleId = permissionIds.RoleId;
                    userPermissions.UserorRole = "Role";
                    // userPermissions.CreatedBy = CreatedBy;
                    userPermissions.CreatedDate = DateTime.Now;
                    userPermissions.Status = true;
                    _context.TblUserPermissions.Add(userPermissions);
                }
            //}
            _context.SaveChanges();
            return new NewRolePermissionResponse { Status = BusinessStatus.Created, Id = userPermissions?.UserPermissionsId.ToString(), ResponseMessage = $"Assigned Permissions successfully!!" };
        }
        /// <summary>
        /// Gets the role permissions.
        /// </summary>
        /// <param name="userPermissionDTO">The user permission dto.</param>
        /// <param name="apiContext">The API context.</param>
        /// <returns></returns>
        public IEnumerable<MasPermissionDTO> GetRolePermissions(UserRoleMapDTO userPermissionDTO, ApiContext apiContext)
        {
            return GetUserRolePermissions(userPermissionDTO, apiContext);
        }

        #endregion

        #region Private Method        
        /// <summary>
        /// Gets the user role permissions.
        /// </summary>
        /// <param name="userPermissionDTO">The user permission dto.</param>
        /// <param name="apiContext">The API context.</param>
        /// <returns></returns>
        private IEnumerable<MasPermissionDTO> GetUserRolePermissions(UserRoleMapDTO userPermissionDTO, ApiContext apiContext)
        {
            _context = (AVOUMContext)DbManager.GetContext(apiContext.ProductType, apiContext.ServerType);
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
                                      RoleId = permission.RoleId,
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
                    var mPermission = menuPermission.FirstOrDefault(m => m.PermissionId == item.PermissionId && m.RoleId == item.RoleId);
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
                               Status = c.Status,
                               RoleId = c.RoleId,
                               RoleName = c.RoleName,
                               Children = GetMenuChildren(menuPermission, c.PermissionId, c.RoleId)
                           });
            return _masPermissionDTOs;
        }
        /// <summary>
        /// Gets the menu children.
        /// </summary>
        /// <param name="permissions">The permissions.</param>
        /// <param name="parentId">The parent identifier.</param>
        /// <param name="roleId">The role identifier.</param>
        /// <returns></returns>
        private IEnumerable<MasPermissionDTO> GetMenuChildren(IEnumerable<MasPermissionDTO> permissions, int parentId, string roleId)
        {
            IEnumerable<MasPermissionDTO> masPermissionDTOs = permissions
                    .Where(c => c.ParentId == parentId && c.RoleId == roleId)
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
                        RoleId = c.RoleId,
                        RoleName = c.RoleName,
                        Status = c.Status,
                        Children = GetMenuChildren(permissions, c.PermissionId, c.RoleId)
                    });
            return masPermissionDTOs;
        }
        /// <summary>
        /// Gets the children.
        /// </summary>
        /// <param name="permissions">The permissions.</param>
        /// <param name="parentId">The parent identifier.</param>
        /// <returns></returns>
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
                        Label = c.ItemDescription,
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

        #endregion
    }
}
