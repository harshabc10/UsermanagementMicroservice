namespace UserManagementMicroservice.Interface
{
    public interface IUserRegistrationModel
    {
        string FirstName { get; set; }
        string LastName { get; set; }
        string Email { get; set; }
        string Password { get; set; }
    }
}
