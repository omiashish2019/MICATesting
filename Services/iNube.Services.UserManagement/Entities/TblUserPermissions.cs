using System;
using System.Collections.Generic;

namespace iNube.Services.UserManagement.Entities
{
    public partial class TblUserPermissions
    {
        public decimal UserPermissionsId { get; set; }
        public int? PermissionId { get; set; }
        public string UserId { get; set; }
        public string RoleId { get; set; }
        public string UserorRole { get; set; }
        public int? SerialNo { get; set; }
        public bool? Status { get; set; }
        public string CreatedBy { get; set; }
        public DateTime? CreatedDate { get; set; }

        public virtual TblMasPermission Permission { get; set; }
        public virtual AspNetRoles Role { get; set; }
        public virtual AspNetUsers User { get; set; }
    }
}
