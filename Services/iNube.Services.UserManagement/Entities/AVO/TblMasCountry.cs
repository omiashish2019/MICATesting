using System;
using System.Collections.Generic;

namespace iNube.Services.UserManagement.Entities.AVO
{
    public partial class TblMasCountry
    {
        public TblMasCountry()
        {
            TblMasState = new HashSet<TblMasState>();
            TblUserAddress = new HashSet<TblUserAddress>();
        }

        public int CountryId { get; set; }
        public string CountryCode { get; set; }
        public string CountryName { get; set; }
        public DateTime? ModifiedDate { get; set; }
        public string ModifiedBy { get; set; }
        public bool? IsActive { get; set; }
        public string ExternalRefCode { get; set; }

        public virtual ICollection<TblMasState> TblMasState { get; set; }
        public virtual ICollection<TblUserAddress> TblUserAddress { get; set; }
    }
}
