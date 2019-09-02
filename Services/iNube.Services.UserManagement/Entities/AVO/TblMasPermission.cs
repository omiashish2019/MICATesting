using System;
using System.Collections.Generic;

namespace iNube.Services.UserManagement.Entities.AVO
{
    public partial class TblMasPermission
    {
        public TblMasPermission()
        {
            TblUserPermissions = new HashSet<TblUserPermissions>();
        }

        public int PermissionId { get; set; }
        public Guid? AppId { get; set; }
        public string ItemType { get; set; }
        public int? ParentId { get; set; }
        public int? MenuId { get; set; }
        public string ItemDescription { get; set; }
        public string Url { get; set; }
        public string PathTo { get; set; }
        public string Collapse { get; set; }
        public string Redirect { get; set; }
        public string State { get; set; }
        public string Mini { get; set; }
        public string Component { get; set; }
        public bool? Status { get; set; }
        public Guid? CreatedBy { get; set; }
        public DateTime? CreatedDate { get; set; }
        public decimal? ItemId { get; set; }
        public bool? IsDeleted { get; set; }
        public string ControllerDesc { get; set; }
        public string ActionDesc { get; set; }
        public string Icon { get; set; }
        public int? Level { get; set; }
        public string Parameter { get; set; }
        public bool? HasFunctional { get; set; }
        public bool? HasFinancial { get; set; }
        public int? SortOrderBy { get; set; }
        public int? Active { get; set; }

        public virtual ICollection<TblUserPermissions> TblUserPermissions { get; set; }
    }
}
