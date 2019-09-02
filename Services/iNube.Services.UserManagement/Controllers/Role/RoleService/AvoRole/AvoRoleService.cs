using AutoMapper;
using iNube.Services.UserManagement.Entities;
using iNube.Services.UserManagement.Helpers;
using iNube.Services.UserManagement.Models;
using iNube.Utility.Framework.Model;
using System;
using System.Collections.Generic;
using System.Linq;

namespace iNube.Services.UserManagement.Controllers.Role.RoleService.MicaRole
{
    public class AvoRoleService : IRoleProductService
    {
        private MICAUMContext _context;
        private IMapper _mapper;
       
        public AvoRoleService(MICAUMContext context, IMapper mapper)
        {
            _context = context;
            _mapper = mapper;
        }

        public IEnumerable<RolesDTO> GetRoles(ApiContext apiContext)
        {
            IEnumerable<AspNetRoles> _roles = _context.AspNetRoles.Select(roles => roles);
            IEnumerable<RolesDTO> _rolesDTOs = _mapper.Map<IEnumerable<RolesDTO>>(_roles);
            foreach (RolesDTO roles in _rolesDTOs)
            {
                roles.Label = roles.Name;
                roles.Value = roles.Id;
            }
            return _rolesDTOs;
        }

        public UserRoleResponse AssignRole(UserRoleMapDTO userRoles, ApiContext apiContext)
        {
            var roledata = _context.AspNetUserRoles.FirstOrDefault(x => x.UserId == userRoles.UserId);
            UserRolesDTO roleDTO = new UserRolesDTO();
            if (userRoles.RoleId != null)
            {
                if (roledata == null)
                {
                    for (int i = 0; i < userRoles.RoleId.Length; i++)
                    {
                        roleDTO.UserId = userRoles.UserId;
                        roleDTO.RoleId = userRoles.RoleId[i];
                        AspNetUserRoles _usersRole = _mapper.Map<AspNetUserRoles>(roleDTO);

                        _context.AspNetUserRoles.Add(_usersRole);
                        // _context.SaveChanges();
                    }
                }
                else
                {
                    var role = _context.AspNetUserRoles.Where(a => a.UserId == userRoles.UserId);
                    foreach (var item in role)
                    {
                        _context.AspNetUserRoles.Remove(item);
                    }
                    for (int i = 0; i < userRoles.RoleId.Length; i++)
                    {
                        roleDTO.UserId = userRoles.UserId;
                        roleDTO.RoleId = userRoles.RoleId[i];
                        AspNetUserRoles _usersRole = _mapper.Map<AspNetUserRoles>(roleDTO);

                        _context.AspNetUserRoles.Add(_usersRole);
                        // _context.SaveChanges();
                    }
                }
                var user = _context.TblUserDetails.SingleOrDefault(x => x.UserId == userRoles.UserId);

                if (string.IsNullOrEmpty(user.RoleId))
                {
                    user.RoleId = userRoles.RoleId[0].ToString();
                }
                _context.SaveChanges();

                //return userRoles;
                return new UserRoleResponse { Status = BusinessStatus.Created, role = userRoles, ResponseMessage = $"Assigned {userRoles.RoleId} Role successfully! " };
            }
            else
            {
                return new UserRoleResponse { Status = BusinessStatus.Error, role = userRoles, ResponseMessage = $"Please select the Role to assign " };
            }
        }

        public IEnumerable<MasPermissionDTO> GetMasPermissions(string perType, ApiContext apiContext)
        {
            IEnumerable<TblMasPermission> _permissions = _context.TblMasPermission.Where(per => per.ItemType == perType);

            var _masPermissionDTOs = GetMenuMasPermissions(_permissions, perType);
            //IEnumerable<MasPermissionDTO> _masPermissionDTOs = _permissions
            //                .Where(c => (c.ParentId == 0 && c.ItemType == perType))
            //                .Select(c => new MasPermissionDTO()
            //                {
            //                    PermissionId = c.PermissionId,
            //                    ItemType = c.ItemType,
            //                    ParentId = c.ParentId,
            //                    MenuId = c.MenuId,
            //                    ItemDescription = c.ItemDescription,
            //                    Url = c.Url,
            //                    PathTo = c.PathTo,
            //                    Collapse = c.Collapse,
            //                    State = c.State,
            //                    Mini = c.Mini,
            //                    Component = c.Component,
            //                    ChildrenDTO = GetChildren(_permissions, c.PermissionId)
            //                });
            //IEnumerable<MasPermissionDTO> _masPermissionDTOs = _mapper.Map<IEnumerable<MasPermissionDTO>>(_permissions);
            return _masPermissionDTOs;
        }
        private IEnumerable<MasPermissionDTO> GetMenuMasPermissions(IEnumerable<TblMasPermission> _permissions, string perType)
        {

            IEnumerable<MasPermissionDTO> _masPermissionDTOs = _permissions
                            .Where(c => (c.ParentId == 0 && c.ItemType == perType))
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
                                Component = c.Component,
                                Children = GetChildren(_permissions, c.PermissionId)
                            });
            // IEnumerable<MasPermissionDTO> _masPermissionDTOs = _mapper.Map<IEnumerable<MasPermissionDTO>>(_permissions);
            return _masPermissionDTOs;
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
                        Label = c.ItemDescription,
                        Url = c.Url,
                        PathTo = c.PathTo,
                        Collapse = c.Collapse,
                        State = c.State,
                        Mini = c.Mini,
                        Component = c.Component,
                        Children = GetChildren(permissions, c.PermissionId)
                    });
            return masPermissionDTOs;
        }

        public IEnumerable<RolesDTO> GetUserRole(string userId  , ApiContext apiContext)
        {
            var userRoles = _context.AspNetUserRoles.Where(u => u.UserId == userId).Select(r => r.RoleId).ToArray();
            IEnumerable<AspNetRoles> _roles = _context.AspNetRoles.Where(r => userRoles.Contains(r.Id)).Select(roles => roles);
            IEnumerable<RolesDTO> _rolesDTOs = _mapper.Map<IEnumerable<RolesDTO>>(_roles);
            foreach (RolesDTO roles in _rolesDTOs)
            {
                roles.Label = roles.Name;
                roles.Value = roles.Id;
            }
            return _rolesDTOs;
        }
        public RoleResponse CreateRole(RolesDTO role, ApiContext apiContext)
        {
            _context = (MICAUMContext)DbManager.GetContext(apiContext.ProductType, apiContext.ServerType);
            var _roles = _mapper.Map<AspNetRoles>(role);
            if (string.IsNullOrEmpty(_roles.Id))
            {
                _roles.Id = Guid.NewGuid().ToString();
                DateTime now = DateTime.Now;
                _roles.ConcurrencyStamp = now.ToString();
                _context.AspNetRoles.Add(_roles);
                _context.SaveChanges();
                var _roleDTOs = _mapper.Map<RolesDTO>(_roles);
                return new RoleResponse { Status = BusinessStatus.Created, roles = _roleDTOs, Id = _roleDTOs.Id, ResponseMessage = $"Role created successfully! \n Role Name with: {_roleDTOs.Name}" };
                //return _roleDTOs;
            }
            else
            {
                _context.AspNetRoles.Update(_roles);
                _context.SaveChanges();
                var _roleDTOs = _mapper.Map<RolesDTO>(_roles);
                return new RoleResponse { Status = BusinessStatus.Created, roles = _roleDTOs, Id = _roleDTOs.Id, ResponseMessage = $"Role modified successfully!" };
                //return _roleDTOs;
            }
        }

    }
}
