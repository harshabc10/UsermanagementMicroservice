

public interface IUserManagementRepo
{
    public Task<bool> RegisterUser(UserEntity user);
    public Task<string> LoginUser(string email, string password);
    public Task<bool> ForgotPassword(string email);
    public Task<bool> ResetPassword(string email, string newPassword);
    public Task<bool> ResetPasswordByOTP(string email, string otp, string newPassword);
    public Task<UserEntity> GetUserById(int userId);
    public Task<bool> DeleteUserByEmail(string email);
}


