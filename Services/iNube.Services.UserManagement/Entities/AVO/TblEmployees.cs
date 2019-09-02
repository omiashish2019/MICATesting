using System;
using System.Collections.Generic;

namespace iNube.Services.UserManagement.Entities.AVO
{
    public partial class TblEmployees
    {
        public int Empid { get; set; }
        public string UserId { get; set; }
        public string UserName { get; set; }
        public decimal? UserParentId { get; set; }
        public bool? Status { get; set; }
        public string CreatedBy { get; set; }
        public DateTime? CreatedDate { get; set; }
        public bool? Locked { get; set; }
        public string LockedReason { get; set; }
        public DateTime? LockStartDate { get; set; }
        public DateTime? LockEndDate { get; set; }
        public bool? LockMechanism { get; set; }
        public decimal? OfficeId { get; set; }
        public string RoleId { get; set; }
        public int? SalutationId { get; set; }
        public string FirstName { get; set; }
        public string MiddleName { get; set; }
        public string LastName { get; set; }
        public int? CountryId { get; set; }
        public int? StateId { get; set; }
        public int? DistrictId { get; set; }
        public int? CityId { get; set; }
        public string AddressLine1 { get; set; }
        public string AddressLine2 { get; set; }
        public string AddressLine3 { get; set; }
        public int? PincodeId { get; set; }
        public string EmployeeNumber { get; set; }
        public DateTime? Dob { get; set; }
        public DateTime? Doj { get; set; }
        public int? GenderId { get; set; }
        public string Email { get; set; }
        public string PassportNumber { get; set; }
        public string DrivingLicenceNumber { get; set; }
        public string ContactNumber { get; set; }
        public int? UserTypeId { get; set; }
        public string PanNo { get; set; }
        public DateTime? LastLoginDateTime { get; set; }
        public bool? IsIos { get; set; }
        public bool? IsAndroid { get; set; }
        public bool? IsWindows { get; set; }
        public bool? IsPasswordChanged { get; set; }
        public string LandLineOffice { get; set; }
        public string LandLineResidence { get; set; }
        public decimal? PartnerId { get; set; }
        public string BranchName { get; set; }
        public string BranchCode { get; set; }
        public string Designation { get; set; }
        public int? MaritalStatusId { get; set; }
    }
}
