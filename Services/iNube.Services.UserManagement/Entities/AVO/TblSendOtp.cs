using System;
using System.Collections.Generic;

namespace iNube.Services.UserManagement.Entities.AVO
{
    public partial class TblSendOtp
    {
        public decimal Id { get; set; }
        public string UserId { get; set; }
        public string Email { get; set; }
        public string Otp { get; set; }
    }
}
