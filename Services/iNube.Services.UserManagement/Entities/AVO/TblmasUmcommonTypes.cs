using System;
using System.Collections.Generic;

namespace iNube.Services.UserManagement.Entities.AVO
{
    public partial class TblmasUmcommonTypes
    {
        public TblmasUmcommonTypes()
        {
            TblUserDetailsGender = new HashSet<TblUserDetails>();
            TblUserDetailsSalutation = new HashSet<TblUserDetails>();
            TblUserDetailsUserType = new HashSet<TblUserDetails>();
        }

        public int CommonTypeId { get; set; }
        public string MasterType { get; set; }
        public string TypeCode { get; set; }
        public string Value { get; set; }

        public virtual ICollection<TblUserDetails> TblUserDetailsGender { get; set; }
        public virtual ICollection<TblUserDetails> TblUserDetailsSalutation { get; set; }
        public virtual ICollection<TblUserDetails> TblUserDetailsUserType { get; set; }
    }
}
