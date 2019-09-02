using iNube.Services.UserManagement.Entities;
using iNube.Services.UserManagement.Models;
using System.Threading.Tasks;

namespace iNube.Services.UserManagement.Controllers.Login.LoginServices
{
    public interface ILoginProductService
    {
        AspNetUsersDTO Authenticate(LoginDTO loginDTO);
        bool GoogleValidate(AspNetUsersDTO asp, string productType, string serverType);
        Task<string> ForgetUserNameAsync(string emailId, string productType, string serverType);
        UserLoginResponse GetUserType(string username, string productType, string serverType);
        LoginResponse GenerateToken(AspNetUsersDTO user, string productType, string serverType);
        Task<bool> SendEmailAsync(EmailTest emailTest);
    }
}
