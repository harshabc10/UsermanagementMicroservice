using System;
using System.Collections.Generic;
using System.Data;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Net.Mail;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Dapper;
using Microsoft.IdentityModel.Tokens;
using MimeKit;

public class UserManagementRepo : IUserManagementRepo
{
    // Static dictionary to store OTPs temporarily in memory
    private static readonly Dictionary<string, string> OTPDictionary = new Dictionary<string, string>();

    private readonly DapperContext _context;
    private readonly IConfiguration _configuration;

    public UserManagementRepo(DapperContext context, IConfiguration configuration)
    {
        _context = context;
        _configuration = configuration;
    }
    //used normal SQL
    /*    public async Task<bool> RegisterUser(UserEntity user)
        {
            // Validate user object
            if (user == null)
                throw new ArgumentNullException(nameof(user), "User object is null");

            if (string.IsNullOrWhiteSpace(user.FirstName))
                throw new ArgumentException("First name is required", nameof(user.FirstName));

            if (string.IsNullOrWhiteSpace(user.LastName))
                throw new ArgumentException("Last name is required", nameof(user.LastName));

            if (string.IsNullOrWhiteSpace(user.Email))
                throw new ArgumentException("Email is required", nameof(user.Email));

            if (string.IsNullOrWhiteSpace(user.Password))
                throw new ArgumentException("Password is required", nameof(user.Password));

            // Hash the password
            string hashedPassword = HashPassword(user.Password);

            // Insert user into the database
            var result = await _context.CreateConnection().ExecuteAsync(
                "INSERT INTO Users (FirstName, LastName, Email, Password, Role, Status) " +
                "VALUES (@FirstName, @LastName, @Email, @Password, @Role, @Status)",
                new { user.FirstName, user.LastName, user.Email, Password = hashedPassword, user.Role }
            );

            return result > 0;
        }*/

    //used stored_procedure
    public async Task<bool> RegisterUser(UserEntity user)
    {
        // Validate user object
        if (user == null)
            throw new ArgumentNullException(nameof(user), "User object is null");

        if (string.IsNullOrWhiteSpace(user.FirstName))
            throw new ArgumentException("First name is required", nameof(user.FirstName));

        if (string.IsNullOrWhiteSpace(user.LastName))
            throw new ArgumentException("Last name is required", nameof(user.LastName));

        if (string.IsNullOrWhiteSpace(user.Email))
            throw new ArgumentException("Email is required", nameof(user.Email));

        if (string.IsNullOrWhiteSpace(user.Password))
            throw new ArgumentException("Password is required", nameof(user.Password));

        // Hash the password
        string hashedPassword = HashPassword(user.Password);

        // Call the stored procedure
        var result = await _context.CreateConnection().ExecuteAsync(
            "RegisterUser",
            new
            {
                FirstName = user.FirstName,
                LastName = user.LastName,
                Email = user.Email,
                Password = hashedPassword,
                Role = user.Role,
            },
            commandType: CommandType.StoredProcedure
        );

        return result > 0;
    }


    private string HashPassword(string password)
    {
        // You can use a library like BCrypt.Net to hash passwords securely
        // Example using BCrypt.Net:
        // return BCrypt.Net.BCrypt.HashPassword(password);

        // For demonstration purposes, let's assume a simple hashing method
        return Convert.ToBase64String(Encoding.UTF8.GetBytes(password));
    }

    /* public async Task<string> LoginUser(string email, string password)
     {
         // Implement your logic to check user credentials and return JWT token
         // Example:
         var user = await _context.CreateConnection().QueryFirstOrDefaultAsync<UserEntity>(
             "SELECT * FROM Users WHERE Email = @Email AND Password = @Password",
             new { Email = email, Password = HashPassword(password) }
         );

         if (user != null)
         {
             // Generate JWT token and return
             var token = GenerateJwtToken(user);
             return token;
         }

         return null; // Invalid credentials
     }*/

    public async Task<string> LoginUser(string email, string password)
    {
        // Implement your logic to check user credentials and return JWT token
        // Example:
        var user = await _context.CreateConnection().QueryFirstOrDefaultAsync<UserEntity>(
            "SELECT * FROM Users WHERE Email = @Email AND Password = @Password",
            new { Email = email, Password = HashPassword(password) }
        );

        if (user != null)
        {
            if (user.Role == "Patient")
            {
                // Generate JWT token and return for patients
                var token = GenerateJwtToken(user);
                return token;
            }
            else if (user.Role == "Doctor")
            {
                // Generate JWT token and return for accepted doctors
                var token = GenerateJwtToken(user);
                return token;
            }
            else if (user.Role == "Admin")
            {
                // Generate JWT token and return for accepted doctors
                var token = GenerateJwtToken(user);
                return token;
            }
            /*else if (user.Role == "Doctor" )
            {
                // Send notification to doctor that they are not authorized to login yet
                // You can implement this notification logic based on your application's requirements

                // Send acceptance mail to the doctor
                await SendAcceptanceEmail(user.Email); // Implement this method

                // Return null as doctor login is pending
                return null;
            }*/
        }

        return null; // Invalid credentials or unauthorized access
    }


    private async Task SendAcceptanceEmail(string email)
    {
        // Construct the email message
        MailMessage message = new MailMessage("harshabc10@outlook.com", email);
        message.Subject = "Doctor Acceptance Notification";
        message.Body = "Dear Doctor,\n\nYour registration has been accepted. You can now log in to the system.";

        // Configure the SMTP client
        SmtpClient client = new SmtpClient("smtp-mail.outlook.com", 587);
        client.UseDefaultCredentials = false;
        client.Credentials = new NetworkCredential("harshabc10@outlook.com", "30thedoctor");
        client.EnableSsl = true;

        try
        {
            // Send the email
            client.Send(message);
            Console.WriteLine("Acceptance email sent successfully.");
        }
        catch (Exception ex)
        {
            // Handle email sending errors
            Console.WriteLine($"Error sending acceptance email: {ex.Message}");
        }
    }

    //forgot password for sending link

  /*  public async Task<bool> ForgotPassword(string email)
    {
        // Validate the email address
        if (string.IsNullOrWhiteSpace(email))
            throw new ArgumentNullException(nameof(email), "Email address is required");

        // Generate a unique token for password reset
        string resetToken = GenerateResetToken();

        // Set an expiration time for the token (e.g., 24 hours from now)
        DateTime expirationTime = DateTime.UtcNow.AddHours(24);

        // Store the token and expiration time securely (e.g., in the database or a distributed cache)

        // Send an email with a link to reset password
        bool emailSent = await SendResetEmail(email, resetToken);

        return emailSent;
    }

    private string GenerateResetToken()
    {
        // Generate a unique token (you can use a library like Guid.NewGuid().ToString() or a JWT token)
        // For example, using Guid:
        return Guid.NewGuid().ToString();
    }

    private async Task<bool> SendResetEmail(string email, string resetToken)
    {
        // Construct the reset password link with the reset token
        string resetLink = $"https://yourapp.com/resetpassword?token={resetToken}";

        // Create the email message
        MailMessage message = new MailMessage("harshabc10@outlook.com", email);
        message.Subject = "Password Reset Request";
        message.Body = $"Dear user,\n\nPlease click the following link to reset your password:\n{resetLink}";

        // Configure the SMTP client
        SmtpClient client = new SmtpClient("smtp-mail.outlook.com", 587);
        client.UseDefaultCredentials = false;
        client.Credentials = new NetworkCredential("harshabc10@outlook.com", "30thedoctor");
        client.EnableSsl = true;

        try
        {
            // Send the email asynchronously
            await client.SendMailAsync(message);
            return true; // Email sent successfully
        }
        catch (Exception ex)
        {
            // Handle email sending errors
            Console.WriteLine($"Error sending email: {ex.Message}");
            return false;
        }
    }*/

    //GET OTP
    public async Task<bool> ForgotPassword(string email)
    {
        // Validate the email address
        if (string.IsNullOrWhiteSpace(email))
            throw new ArgumentNullException(nameof(email), "Email address is required");

        // Generate an OTP for password reset
        string otp = GenerateOtp();

        // Store the OTP in the dictionary
        OTPDictionary[email] = otp;

        //to get the otp at console
        await Console.Out.WriteLineAsync(otp);

        // Set an expiration time for the OTP (e.g., 10 minutes from now)
        DateTime expirationTime = DateTime.UtcNow.AddMinutes(10);

        // Send the OTP via email (assuming you have an email sending method)
        bool otpSent = await SendResetOtp(email, otp);

        return otpSent; // OTP generation and storage successful
    }


    private string GenerateOtp()
    {
        // Generate a random 6-digit OTP
        Random random = new Random();
        int otpNumber = random.Next(100000, 999999);
        return otpNumber.ToString();
    }

    private async Task<bool> SendResetOtp(string email, string otp)
    {
        // Create the email message
        MailMessage message = new MailMessage("harshabc10@outlook.com", email);
        message.Subject = "Password Reset OTP";
        message.Body = $"Dear user,\n\nYour OTP for password reset is: {otp}";

        // Configure the SMTP client
        SmtpClient client = new SmtpClient("smtp-mail.outlook.com", 587);
        client.UseDefaultCredentials = false;
        client.Credentials = new NetworkCredential("harshabc10@outlook.com", "30thedoctor");
        client.EnableSsl = true;

        try
        {
            // Send the email asynchronously
            await client.SendMailAsync(message);
            return true; // OTP sent successfully
        }
        catch (Exception ex)
        {
            // Handle email sending errors
            Console.WriteLine($"Error sending OTP: {ex.Message}");
            return false;
        }
    }

    public async Task<bool> ResetPassword(string email, string newPassword)
    {
        // Implement your logic to reset user password
        // Example:
        var result = await _context.CreateConnection().ExecuteAsync(
            "UPDATE Users SET Password = @NewPassword WHERE Email = @Email",
            new { NewPassword = HashPassword(newPassword), Email = email }
        );
        return result > 0;
    }

    private string GenerateJwtToken(UserEntity user)
    {
        var claims = new List<Claim>
        {
            new Claim(ClaimTypes.Role, $"{user.Role}"),
            new Claim(ClaimTypes.NameIdentifier, $"{user.UserId}"),
            new Claim(ClaimTypes.NameIdentifier, $"{user.Email}")
            
        };

        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:SecretKey"]));
        var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
        var expires = DateTime.UtcNow.AddHours(1);

        var token = new JwtSecurityToken(
            issuer: _configuration["Jwt:Issuer"],
            audience: _configuration["Jwt:Audience"],
            claims: claims,
            expires: expires,
            signingCredentials: credentials
        );

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    public async Task<bool> ResetPasswordByOTP(string email, string otp, string newPassword)
    {
        // Validate the email address
        if (string.IsNullOrWhiteSpace(email))
            throw new ArgumentNullException(nameof(email), "Email address is required");

        // Validate the OTP
        if (string.IsNullOrWhiteSpace(otp))
            throw new ArgumentNullException(nameof(otp), "OTP is required");

        // Verify the OTP (e.g., compare it with a stored OTP)
        if (OTPDictionary.TryGetValue(email, out string storedOTP))
        {
            // Compare the input OTP with the stored OTP
            bool otpMatch = otp.Equals(storedOTP, StringComparison.OrdinalIgnoreCase);

            // Remove the OTP from the dictionary after verification
            OTPDictionary.Remove(email);

            if (otpMatch)
            {
                // Implement your logic to reset user password using OTP
                // Example:
                var result = await _context.CreateConnection().ExecuteAsync(
                    "UPDATE Users SET Password = @NewPassword WHERE Email = @Email",
                    new { NewPassword = HashPassword(newPassword), Email = email }
                );
                return result > 0;
            }
        }

        return false; // OTP verification failed
    }


    public async Task<UserEntity> GetUserById(int userId)
    {
        // Implement your logic to get a user by ID from the database
        // Example:
        var user = await _context.CreateConnection().QueryFirstOrDefaultAsync<UserEntity>(
            "SELECT * FROM Users WHERE UserId = @UserId",
            new { UserId = userId }
        );
        return user;
    }

    public async Task<bool> DeleteUserByEmail(string email)
    {
        // Validate the email address
        if (string.IsNullOrWhiteSpace(email))
            throw new ArgumentNullException(nameof(email), "Email address is required");

        // Implement your logic to delete a user by email from the database
        // Example:
        var result = await _context.CreateConnection().ExecuteAsync(
            "DELETE FROM Users WHERE Email = @Email",
            new { Email = email }
        );
        return result > 0;
    }

}
