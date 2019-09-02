using System;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata;

namespace iNube.Services.UserManagement.Entities.AVO
{
    public partial class AVOUMContext : DbContext
    {
        public AVOUMContext()
        {
        }

        public AVOUMContext(DbContextOptions<AVOUMContext> options)
            : base(options)
        {
        }

        public virtual DbSet<AspNetRoleClaims> AspNetRoleClaims { get; set; }
        public virtual DbSet<AspNetRoles> AspNetRoles { get; set; }
        public virtual DbSet<AspNetUserClaims> AspNetUserClaims { get; set; }
        public virtual DbSet<AspNetUserLogins> AspNetUserLogins { get; set; }
        public virtual DbSet<AspNetUserRoles> AspNetUserRoles { get; set; }
        public virtual DbSet<AspNetUserTokens> AspNetUserTokens { get; set; }
        public virtual DbSet<AspNetUsers> AspNetUsers { get; set; }
        public virtual DbSet<TblEmployees> TblEmployees { get; set; }
        public virtual DbSet<TblMasCity> TblMasCity { get; set; }
        public virtual DbSet<TblMasCountry> TblMasCountry { get; set; }
        public virtual DbSet<TblMasDistrict> TblMasDistrict { get; set; }
        public virtual DbSet<TblMasPermission> TblMasPermission { get; set; }
        public virtual DbSet<TblMasPinCode> TblMasPinCode { get; set; }
        public virtual DbSet<TblMasState> TblMasState { get; set; }
        public virtual DbSet<TblSendOtp> TblSendOtp { get; set; }
        public virtual DbSet<TblUserAddress> TblUserAddress { get; set; }
        public virtual DbSet<TblUserDetails> TblUserDetails { get; set; }
        public virtual DbSet<TblUserPermissions> TblUserPermissions { get; set; }
        public virtual DbSet<TblmasUmcommonTypes> TblmasUmcommonTypes { get; set; }

        protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
        {
            if (!optionsBuilder.IsConfigured)
            {
#warning To protect potentially sensitive information in your connection string, you should move it out of source code. See http://go.microsoft.com/fwlink/?LinkId=723263 for guidance on storing connection strings.
                optionsBuilder.UseSqlServer("Server=inubesql.database.windows.net;Database=AVOLifeP2;User ID=AVOLifeUserP2;Password=AVOLife*User123;");
            }
        }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            modelBuilder.HasAnnotation("ProductVersion", "2.2.2-servicing-10034");

            modelBuilder.Entity<AspNetRoleClaims>(entity =>
            {
                entity.ToTable("AspNetRoleClaims", "UM");

                entity.Property(e => e.RoleId)
                    .IsRequired()
                    .HasMaxLength(450);

                entity.HasOne(d => d.Role)
                    .WithMany(p => p.AspNetRoleClaims)
                    .HasForeignKey(d => d.RoleId);
            });

            modelBuilder.Entity<AspNetRoles>(entity =>
            {
                entity.ToTable("AspNetRoles", "UM");

                entity.Property(e => e.Id).ValueGeneratedNever();

                entity.Property(e => e.Name).HasMaxLength(256);

                entity.Property(e => e.NormalizedName).HasMaxLength(256);
            });

            modelBuilder.Entity<AspNetUserClaims>(entity =>
            {
                entity.ToTable("AspNetUserClaims", "UM");

                entity.Property(e => e.UserId)
                    .IsRequired()
                    .HasMaxLength(450);

                entity.HasOne(d => d.User)
                    .WithMany(p => p.AspNetUserClaims)
                    .HasForeignKey(d => d.UserId);
            });

            modelBuilder.Entity<AspNetUserLogins>(entity =>
            {
                entity.HasKey(e => new { e.LoginProvider, e.ProviderKey });

                entity.ToTable("AspNetUserLogins", "UM");

                entity.Property(e => e.LoginProvider).HasMaxLength(128);

                entity.Property(e => e.ProviderKey).HasMaxLength(128);

                entity.Property(e => e.UserId)
                    .IsRequired()
                    .HasMaxLength(450);

                entity.HasOne(d => d.User)
                    .WithMany(p => p.AspNetUserLogins)
                    .HasForeignKey(d => d.UserId);
            });

            modelBuilder.Entity<AspNetUserRoles>(entity =>
            {
                entity.HasKey(e => new { e.UserId, e.RoleId });

                entity.ToTable("AspNetUserRoles", "UM");

                entity.HasOne(d => d.Role)
                    .WithMany(p => p.AspNetUserRoles)
                    .HasForeignKey(d => d.RoleId);

                entity.HasOne(d => d.User)
                    .WithMany(p => p.AspNetUserRoles)
                    .HasForeignKey(d => d.UserId);
            });

            modelBuilder.Entity<AspNetUserTokens>(entity =>
            {
                entity.HasKey(e => new { e.UserId, e.LoginProvider, e.Name });

                entity.ToTable("AspNetUserTokens", "UM");

                entity.Property(e => e.LoginProvider).HasMaxLength(128);

                entity.Property(e => e.Name).HasMaxLength(128);

                entity.HasOne(d => d.User)
                    .WithMany(p => p.AspNetUserTokens)
                    .HasForeignKey(d => d.UserId);
            });

            modelBuilder.Entity<AspNetUsers>(entity =>
            {
                entity.ToTable("AspNetUsers", "UM");

                entity.Property(e => e.Id).ValueGeneratedNever();

                entity.Property(e => e.Email).HasMaxLength(256);

                entity.Property(e => e.NormalizedEmail).HasMaxLength(256);

                entity.Property(e => e.NormalizedUserName).HasMaxLength(256);

                entity.Property(e => e.UserName).HasMaxLength(256);
            });

            modelBuilder.Entity<TblEmployees>(entity =>
            {
                entity.HasKey(e => e.Empid)
                    .HasName("PK_tblemployees");

                entity.ToTable("tblEmployees", "UM");

                entity.Property(e => e.Empid).ValueGeneratedNever();

                entity.Property(e => e.AddressLine1)
                    .HasMaxLength(200)
                    .IsUnicode(false);

                entity.Property(e => e.AddressLine2)
                    .HasMaxLength(200)
                    .IsUnicode(false);

                entity.Property(e => e.AddressLine3)
                    .HasMaxLength(200)
                    .IsUnicode(false);

                entity.Property(e => e.BranchCode)
                    .HasMaxLength(50)
                    .IsUnicode(false);

                entity.Property(e => e.BranchName)
                    .HasMaxLength(100)
                    .IsUnicode(false);

                entity.Property(e => e.ContactNumber)
                    .HasMaxLength(15)
                    .IsUnicode(false);

                entity.Property(e => e.CreatedBy).HasMaxLength(450);

                entity.Property(e => e.CreatedDate).HasColumnType("datetime");

                entity.Property(e => e.Designation)
                    .HasMaxLength(25)
                    .IsUnicode(false);

                entity.Property(e => e.Dob)
                    .HasColumnName("DOB")
                    .HasColumnType("date");

                entity.Property(e => e.Doj)
                    .HasColumnName("DOJ")
                    .HasColumnType("date");

                entity.Property(e => e.DrivingLicenceNumber)
                    .HasMaxLength(20)
                    .IsUnicode(false);

                entity.Property(e => e.Email)
                    .HasMaxLength(100)
                    .IsUnicode(false);

                entity.Property(e => e.EmployeeNumber)
                    .HasMaxLength(255)
                    .IsUnicode(false);

                entity.Property(e => e.FirstName)
                    .HasMaxLength(100)
                    .IsUnicode(false);

                entity.Property(e => e.IsIos).HasColumnName("IsIOS");

                entity.Property(e => e.LandLineOffice)
                    .HasMaxLength(15)
                    .IsUnicode(false);

                entity.Property(e => e.LandLineResidence)
                    .HasMaxLength(15)
                    .IsUnicode(false);

                entity.Property(e => e.LastLoginDateTime).HasColumnType("datetime");

                entity.Property(e => e.LastName)
                    .HasMaxLength(100)
                    .IsUnicode(false);

                entity.Property(e => e.LockEndDate)
                    .HasColumnName("lockEndDate")
                    .HasColumnType("datetime");

                entity.Property(e => e.LockStartDate)
                    .HasColumnName("lockStartDate")
                    .HasColumnType("datetime");

                entity.Property(e => e.LockedReason)
                    .HasMaxLength(500)
                    .IsUnicode(false);

                entity.Property(e => e.MiddleName)
                    .HasMaxLength(100)
                    .IsUnicode(false);

                entity.Property(e => e.OfficeId)
                    .HasColumnName("OfficeID")
                    .HasColumnType("numeric(18, 0)");

                entity.Property(e => e.PanNo)
                    .HasMaxLength(250)
                    .IsUnicode(false);

                entity.Property(e => e.PartnerId).HasColumnType("numeric(18, 0)");

                entity.Property(e => e.PassportNumber)
                    .HasMaxLength(20)
                    .IsUnicode(false);

                entity.Property(e => e.RoleId).HasMaxLength(450);

                entity.Property(e => e.UserId)
                    .HasColumnName("UserID")
                    .HasMaxLength(450);

                entity.Property(e => e.UserName)
                    .HasMaxLength(255)
                    .IsUnicode(false);

                entity.Property(e => e.UserParentId).HasColumnType("numeric(18, 0)");
            });

            modelBuilder.Entity<TblMasCity>(entity =>
            {
                entity.HasKey(e => e.CityId);

                entity.ToTable("tblMasCity", "UM");

                entity.Property(e => e.CityId)
                    .HasColumnName("CityID")
                    .ValueGeneratedNever();

                entity.Property(e => e.CityCode)
                    .HasMaxLength(50)
                    .IsUnicode(false);

                entity.Property(e => e.CityName)
                    .HasMaxLength(200)
                    .IsUnicode(false);

                entity.Property(e => e.DistrictId).HasColumnName("DistrictID");

                entity.Property(e => e.ExternalRefCode)
                    .HasMaxLength(50)
                    .IsUnicode(false);

                entity.Property(e => e.ModifiedBy)
                    .HasMaxLength(50)
                    .IsUnicode(false);

                entity.Property(e => e.ModifiedDate).HasColumnType("datetime");

                entity.Property(e => e.Pincode)
                    .HasMaxLength(10)
                    .IsUnicode(false);

                entity.HasOne(d => d.District)
                    .WithMany(p => p.TblMasCity)
                    .HasForeignKey(d => d.DistrictId)
                    .HasConstraintName("FK_tblMasCity_tblMasDistrict");
            });

            modelBuilder.Entity<TblMasCountry>(entity =>
            {
                entity.HasKey(e => e.CountryId);

                entity.ToTable("tblMasCountry", "UM");

                entity.Property(e => e.CountryId)
                    .HasColumnName("CountryID")
                    .ValueGeneratedNever();

                entity.Property(e => e.CountryCode)
                    .HasMaxLength(50)
                    .IsUnicode(false);

                entity.Property(e => e.CountryName)
                    .HasMaxLength(200)
                    .IsUnicode(false);

                entity.Property(e => e.ExternalRefCode)
                    .HasMaxLength(50)
                    .IsUnicode(false);

                entity.Property(e => e.ModifiedBy)
                    .HasMaxLength(50)
                    .IsUnicode(false);

                entity.Property(e => e.ModifiedDate).HasColumnType("datetime");
            });

            modelBuilder.Entity<TblMasDistrict>(entity =>
            {
                entity.HasKey(e => e.DistrictId);

                entity.ToTable("tblMasDistrict", "UM");

                entity.Property(e => e.DistrictId)
                    .HasColumnName("DistrictID")
                    .ValueGeneratedNever();

                entity.Property(e => e.DistrictCode)
                    .HasMaxLength(50)
                    .IsUnicode(false);

                entity.Property(e => e.DistrictName)
                    .HasMaxLength(200)
                    .IsUnicode(false);

                entity.Property(e => e.ExternalRefCode)
                    .HasMaxLength(50)
                    .IsUnicode(false);

                entity.Property(e => e.ModifiedBy)
                    .HasMaxLength(50)
                    .IsUnicode(false);

                entity.Property(e => e.ModifiedDate).HasColumnType("datetime");

                entity.Property(e => e.StateId).HasColumnName("StateID");

                entity.HasOne(d => d.State)
                    .WithMany(p => p.TblMasDistrict)
                    .HasForeignKey(d => d.StateId)
                    .HasConstraintName("FK_tblMasDistrict_tblMasState");
            });

            modelBuilder.Entity<TblMasPermission>(entity =>
            {
                entity.HasKey(e => e.PermissionId);

                entity.ToTable("tblMasPermission", "UM");

                entity.Property(e => e.PermissionId)
                    .HasColumnName("PermissionID")
                    .ValueGeneratedNever();

                entity.Property(e => e.ActionDesc)
                    .HasMaxLength(500)
                    .IsUnicode(false);

                entity.Property(e => e.AppId).HasColumnName("AppID");

                entity.Property(e => e.Collapse)
                    .HasMaxLength(100)
                    .IsUnicode(false);

                entity.Property(e => e.Component)
                    .HasMaxLength(100)
                    .IsUnicode(false);

                entity.Property(e => e.ControllerDesc)
                    .HasMaxLength(500)
                    .IsUnicode(false);

                entity.Property(e => e.CreatedDate).HasColumnType("datetime");

                entity.Property(e => e.Icon)
                    .HasMaxLength(255)
                    .IsUnicode(false);

                entity.Property(e => e.ItemDescription)
                    .HasMaxLength(255)
                    .IsUnicode(false);

                entity.Property(e => e.ItemId)
                    .HasColumnName("ItemID")
                    .HasColumnType("numeric(18, 0)");

                entity.Property(e => e.ItemType)
                    .HasMaxLength(255)
                    .IsUnicode(false);

                entity.Property(e => e.MenuId).HasColumnName("MenuID");

                entity.Property(e => e.Mini)
                    .HasColumnName("mini")
                    .HasMaxLength(100)
                    .IsUnicode(false);

                entity.Property(e => e.Parameter)
                    .HasColumnName("parameter")
                    .HasMaxLength(255)
                    .IsUnicode(false);

                entity.Property(e => e.PathTo)
                    .HasMaxLength(500)
                    .IsUnicode(false);

                entity.Property(e => e.Redirect)
                    .HasMaxLength(100)
                    .IsUnicode(false);

                entity.Property(e => e.State)
                    .HasMaxLength(100)
                    .IsUnicode(false);

                entity.Property(e => e.Url)
                    .HasColumnName("url")
                    .HasMaxLength(500)
                    .IsUnicode(false);
            });

            modelBuilder.Entity<TblMasPinCode>(entity =>
            {
                entity.HasKey(e => e.PincodeId)
                    .HasName("PK_tblMasPincode");

                entity.ToTable("tblMasPinCode", "UM");

                entity.Property(e => e.PincodeId)
                    .HasColumnName("PincodeID")
                    .ValueGeneratedNever();

                entity.Property(e => e.AreaName)
                    .HasMaxLength(200)
                    .IsUnicode(false);

                entity.Property(e => e.CityId).HasColumnName("CityID");

                entity.Property(e => e.ExternalRefCode)
                    .HasMaxLength(50)
                    .IsUnicode(false);

                entity.Property(e => e.ModifiedBy)
                    .HasMaxLength(50)
                    .IsUnicode(false);

                entity.Property(e => e.ModifiedDate).HasColumnType("datetime");

                entity.Property(e => e.Pincode)
                    .HasMaxLength(10)
                    .IsUnicode(false);

                entity.HasOne(d => d.City)
                    .WithMany(p => p.TblMasPinCode)
                    .HasForeignKey(d => d.CityId)
                    .HasConstraintName("FK_tblMasPincode_tblMasCity");
            });

            modelBuilder.Entity<TblMasState>(entity =>
            {
                entity.HasKey(e => e.StateId);

                entity.ToTable("tblMasState", "UM");

                entity.Property(e => e.StateId)
                    .HasColumnName("StateID")
                    .ValueGeneratedNever();

                entity.Property(e => e.CountryId).HasColumnName("CountryID");

                entity.Property(e => e.ExternalRefCode)
                    .HasMaxLength(50)
                    .IsUnicode(false);

                entity.Property(e => e.ModifiedBy)
                    .HasMaxLength(50)
                    .IsUnicode(false);

                entity.Property(e => e.ModifiedDate).HasColumnType("datetime");

                entity.Property(e => e.StateCode)
                    .HasMaxLength(50)
                    .IsUnicode(false);

                entity.Property(e => e.StateName)
                    .HasMaxLength(200)
                    .IsUnicode(false);

                entity.HasOne(d => d.Country)
                    .WithMany(p => p.TblMasState)
                    .HasForeignKey(d => d.CountryId)
                    .HasConstraintName("FK_tblMasState_tblMasCountry");
            });

            modelBuilder.Entity<TblSendOtp>(entity =>
            {
                entity.ToTable("tblSendOTP", "UM");

                entity.Property(e => e.Id)
                    .HasColumnType("numeric(18, 0)")
                    .ValueGeneratedOnAdd();

                entity.Property(e => e.Email).HasMaxLength(256);

                entity.Property(e => e.Otp)
                    .HasColumnName("OTP")
                    .HasMaxLength(250);

                entity.Property(e => e.UserId).HasMaxLength(256);
            });

            modelBuilder.Entity<TblUserAddress>(entity =>
            {
                entity.HasKey(e => e.UserAddressId);

                entity.ToTable("tblUserAddress", "UM");

                entity.Property(e => e.UserAddressId)
                    .HasColumnName("UserAddressID")
                    .HasColumnType("numeric(18, 0)")
                    .ValueGeneratedOnAdd();

                entity.Property(e => e.Id).HasMaxLength(450);

                entity.Property(e => e.UserAddressLine1)
                    .HasMaxLength(200)
                    .IsUnicode(false);

                entity.Property(e => e.UserAddressLine2)
                    .HasMaxLength(200)
                    .IsUnicode(false);

                entity.Property(e => e.UserAddressLine3)
                    .HasMaxLength(200)
                    .IsUnicode(false);

                entity.Property(e => e.UserAddressType)
                    .HasMaxLength(1)
                    .IsUnicode(false);

                entity.HasOne(d => d.IdNavigation)
                    .WithMany(p => p.TblUserAddress)
                    .HasForeignKey(d => d.Id)
                    .HasConstraintName("FK_tblUserAddress_AspNetUsers");

                entity.HasOne(d => d.UserCity)
                    .WithMany(p => p.TblUserAddress)
                    .HasForeignKey(d => d.UserCityId)
                    .HasConstraintName("FK_tblUserAddress_tblMasCity");

                entity.HasOne(d => d.UserCountry)
                    .WithMany(p => p.TblUserAddress)
                    .HasForeignKey(d => d.UserCountryId)
                    .HasConstraintName("FK_tblUserAddress_tblMasCountry");

                entity.HasOne(d => d.UserDistrict)
                    .WithMany(p => p.TblUserAddress)
                    .HasForeignKey(d => d.UserDistrictId)
                    .HasConstraintName("FK_tblUserAddress_tblMasDistrict");

                entity.HasOne(d => d.UserPincode)
                    .WithMany(p => p.TblUserAddress)
                    .HasForeignKey(d => d.UserPincodeId)
                    .HasConstraintName("FK_tblUserAddress_tblMasPinCode");

                entity.HasOne(d => d.UserState)
                    .WithMany(p => p.TblUserAddress)
                    .HasForeignKey(d => d.UserStateId)
                    .HasConstraintName("FK_tblUserAddress_tblMasState");
            });

            modelBuilder.Entity<TblUserDetails>(entity =>
            {
                entity.HasKey(e => e.NodeId);

                entity.ToTable("tblUserDetails", "UM");

                entity.Property(e => e.NodeId)
                    .HasColumnName("NodeID")
                    .HasColumnType("numeric(18, 0)")
                    .ValueGeneratedOnAdd();

                entity.Property(e => e.BranchCode)
                    .HasMaxLength(50)
                    .IsUnicode(false);

                entity.Property(e => e.BranchName)
                    .HasMaxLength(100)
                    .IsUnicode(false);

                entity.Property(e => e.ContactNumber)
                    .HasMaxLength(15)
                    .IsUnicode(false);

                entity.Property(e => e.CreatedBy).HasMaxLength(450);

                entity.Property(e => e.CreatedDate).HasColumnType("datetime");

                entity.Property(e => e.Designation)
                    .HasMaxLength(25)
                    .IsUnicode(false);

                entity.Property(e => e.Dob)
                    .HasColumnName("DOB")
                    .HasColumnType("date");

                entity.Property(e => e.Doj)
                    .HasColumnName("DOJ")
                    .HasColumnType("date");

                entity.Property(e => e.DrivingLicenceNumber)
                    .HasMaxLength(20)
                    .IsUnicode(false);

                entity.Property(e => e.Email)
                    .HasMaxLength(100)
                    .IsUnicode(false);

                entity.Property(e => e.EmployeeNumber)
                    .HasMaxLength(255)
                    .IsUnicode(false);

                entity.Property(e => e.FirstName)
                    .HasMaxLength(100)
                    .IsUnicode(false);

                entity.Property(e => e.IsIos).HasColumnName("IsIOS");

                entity.Property(e => e.LandLineOffice)
                    .HasMaxLength(15)
                    .IsUnicode(false);

                entity.Property(e => e.LandLineResidence)
                    .HasMaxLength(15)
                    .IsUnicode(false);

                entity.Property(e => e.LastLoginDateTime).HasColumnType("datetime");

                entity.Property(e => e.LastName)
                    .HasMaxLength(100)
                    .IsUnicode(false);

                entity.Property(e => e.LockEndDate)
                    .HasColumnName("lockEndDate")
                    .HasColumnType("datetime");

                entity.Property(e => e.LockStartDate)
                    .HasColumnName("lockStartDate")
                    .HasColumnType("datetime");

                entity.Property(e => e.LockedReason)
                    .HasMaxLength(500)
                    .IsUnicode(false);

                entity.Property(e => e.MiddleName)
                    .HasMaxLength(100)
                    .IsUnicode(false);

                entity.Property(e => e.OfficeId)
                    .HasColumnName("OfficeID")
                    .HasColumnType("numeric(18, 0)");

                entity.Property(e => e.OrganizationId)
                    .HasColumnName("OrganizationID")
                    .HasColumnType("numeric(18, 0)");

                entity.Property(e => e.PanNo)
                    .HasMaxLength(250)
                    .IsUnicode(false);

                entity.Property(e => e.PartnerId).HasColumnType("numeric(18, 0)");

                entity.Property(e => e.PartnerName).HasMaxLength(50);

                entity.Property(e => e.PassportNumber)
                    .HasMaxLength(20)
                    .IsUnicode(false);

                entity.Property(e => e.RoleId).HasMaxLength(450);

                entity.Property(e => e.UserId)
                    .HasColumnName("UserID")
                    .HasMaxLength(450);

                entity.Property(e => e.UserName)
                    .HasMaxLength(255)
                    .IsUnicode(false);

                entity.Property(e => e.UserParentId).HasColumnType("numeric(18, 0)");

                entity.HasOne(d => d.Gender)
                    .WithMany(p => p.TblUserDetailsGender)
                    .HasForeignKey(d => d.GenderId)
                    .HasConstraintName("FK_tblUserDetails_tblmasUMCommonTypes_Gender");

                entity.HasOne(d => d.Role)
                    .WithMany(p => p.TblUserDetails)
                    .HasForeignKey(d => d.RoleId)
                    .HasConstraintName("FK_tblUserDetails_AspNetRoles");

                entity.HasOne(d => d.Salutation)
                    .WithMany(p => p.TblUserDetailsSalutation)
                    .HasForeignKey(d => d.SalutationId)
                    .HasConstraintName("FK_tblUserDetails_tblmasUMCommonTypes_Salutation");

                entity.HasOne(d => d.User)
                    .WithMany(p => p.TblUserDetails)
                    .HasForeignKey(d => d.UserId)
                    .HasConstraintName("FK_tblUserDetails_AspNetUsers");

                entity.HasOne(d => d.UserParent)
                    .WithMany(p => p.InverseUserParent)
                    .HasForeignKey(d => d.UserParentId)
                    .HasConstraintName("FK_tblUserDetails_tblUserDetails");

                entity.HasOne(d => d.UserType)
                    .WithMany(p => p.TblUserDetailsUserType)
                    .HasForeignKey(d => d.UserTypeId)
                    .HasConstraintName("FK_tblUserDetails_tblmasUMCommonTypes");
            });

            modelBuilder.Entity<TblUserPermissions>(entity =>
            {
                entity.HasKey(e => e.UserPermissionsId)
                    .HasName("PK__tblUserPermissions");

                entity.ToTable("tblUserPermissions", "UM");

                entity.Property(e => e.UserPermissionsId)
                    .HasColumnName("UserPermissionsID")
                    .HasColumnType("numeric(18, 0)")
                    .ValueGeneratedOnAdd();

                entity.Property(e => e.CreatedBy).HasMaxLength(450);

                entity.Property(e => e.CreatedDate).HasColumnType("datetime");

                entity.Property(e => e.RoleId).HasMaxLength(450);

                entity.Property(e => e.UserId)
                    .HasColumnName("UserID")
                    .HasMaxLength(450);

                entity.Property(e => e.UserorRole)
                    .HasMaxLength(50)
                    .IsUnicode(false);

                entity.HasOne(d => d.Permission)
                    .WithMany(p => p.TblUserPermissions)
                    .HasForeignKey(d => d.PermissionId)
                    .HasConstraintName("fk_UserPermissionsID");

                entity.HasOne(d => d.Role)
                    .WithMany(p => p.TblUserPermissions)
                    .HasForeignKey(d => d.RoleId)
                    .HasConstraintName("fk_tblUserPermissionRole");

                entity.HasOne(d => d.User)
                    .WithMany(p => p.TblUserPermissions)
                    .HasForeignKey(d => d.UserId)
                    .HasConstraintName("fk_tblUserPermissions");
            });

            modelBuilder.Entity<TblmasUmcommonTypes>(entity =>
            {
                entity.HasKey(e => e.CommonTypeId);

                entity.ToTable("tblmasUMCommonTypes", "UM");

                entity.Property(e => e.CommonTypeId)
                    .HasColumnName("CommonTypeID")
                    .ValueGeneratedNever();

                entity.Property(e => e.MasterType).HasMaxLength(50);

                entity.Property(e => e.TypeCode).HasMaxLength(50);

                entity.Property(e => e.Value).HasMaxLength(200);
            });
        }
    }
}
