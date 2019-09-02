using System;
using System.Collections.Generic;

namespace iNube.Services.UserManagement.Entities.AVO
{
    public partial class TblUserAddress
    {
        public decimal UserAddressId { get; set; }
        public string Id { get; set; }
        public string UserAddressType { get; set; }
        public int? UserCountryId { get; set; }
        public int? UserStateId { get; set; }
        public int? UserDistrictId { get; set; }
        public int? UserCityId { get; set; }
        public string UserAddressLine1 { get; set; }
        public string UserAddressLine2 { get; set; }
        public string UserAddressLine3 { get; set; }
        public int? UserPincodeId { get; set; }

        public virtual AspNetUsers IdNavigation { get; set; }
        public virtual TblMasCity UserCity { get; set; }
        public virtual TblMasCountry UserCountry { get; set; }
        public virtual TblMasDistrict UserDistrict { get; set; }
        public virtual TblMasPinCode UserPincode { get; set; }
        public virtual TblMasState UserState { get; set; }
    }
}
