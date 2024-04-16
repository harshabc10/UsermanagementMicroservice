using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using UserManagementMicroservice.DTO;

[ApiController]
[Route("api/[controller]")]
public class UserController : ControllerBase
{
    private readonly IUserManagementRepo _userManagementServices;

    public UserController(IUserManagementRepo userManagementServices)
    {
        _userManagementServices = userManagementServices;
        
    }

    [HttpPost("register/patient")]
    public async Task<IActionResult> RegisterPatient(PatientRegistrationModel model)
    {
        // You can add validation logic for the model here

        // Create a UserEntity for the patient
        var user = new UserEntity
        {
            FirstName = model.FirstName,
            LastName = model.LastName,
            Email = model.Email,
            Password = model.Password,
            Role = "Patient" // Assigning the role directly for patients
        };

        var result = await _userManagementServices.RegisterUser(user);
        if (result)
            return Ok("Patient registered successfully");
        return BadRequest("Patient registration failed");
    }

    [HttpPost("register/doctor")]
    public async Task<IActionResult> RegisterDoctor(DoctorRegistrationModel model)
    {
        // You can add validation logic for the model here

        // Create a UserEntity for the doctor
        var user = new UserEntity
        {
            FirstName = model.FirstName,
            LastName = model.LastName,
            Email = model.Email,
            Password = model.Password,
            Role = "Doctor" // Assigning the role directly for doctors
        };

        var result = await _userManagementServices.RegisterUser(user);
        if (result)
            return Ok("Doctor registered successfully");
        return BadRequest("Doctor registration failed");
    }

    [HttpPost("login")]
    public async Task<IActionResult> LoginUser(LoginRequestModel model)
    {
        var token = await _userManagementServices.LoginUser(model.Email, model.Password);
        if (token != null)
            return Ok(new { Token = token });
        return Unauthorized("Invalid credentials");
    }

    [HttpGet("getuser/{userId}")]
    public async Task<IActionResult> GetUserById(int userId)
    {
        var user = await _userManagementServices.GetUserById(userId);
        if (user != null)
            return Ok(user);
        return NotFound("User not found");
    }



    /*    [HttpPost("forgotpassword")]
        public async Task<IActionResult> ForgotPassword(ForgotPasswordRequestModel model)
        {
            var result = await _userManagementServices.ForgotPassword(model.Email);
            if (result)
                //FOR LINK
    *//*            return Ok("Password reset link sent to your email");*//*
            //FOR OTP
                return Ok("Password reset OTP sent to your email");
            return BadRequest("Failed to process your request");
        }*/
    /*
        [HttpPut("Resetpassword_By_EmailId")]
        public async Task<IActionResult> ResetPassword(ResetPasswordRequestModel model)
        {
            var result = await _userManagementServices.ResetPassword(model.Email, model.NewPassword);
            if (result)
                return Ok("Password reset successful");
            return BadRequest("Failed to reset password");
        }*/

    /*    [HttpPut("resetpasswordbyotp")]
        public async Task<IActionResult> ResetPasswordByOTP(ResetPasswordByOTPRequestModel model)
        {
            var result = await _userManagementServices.ResetPasswordByOTP(model.Email, model.OTP, model.NewPassword);
            if (result)
                return Ok("Password reset successful");
            return BadRequest("Failed to reset password");
        }
    */


    /*    [HttpDelete("deleteuser")]
        public async Task<IActionResult> DeleteUserByEmail(string email)
        {
            var result = await _userManagementServices.DeleteUserByEmail(email);
            if (result)
                return Ok("User deleted successfully");
            return NotFound("User not found");
        }*/

    // Implement APIs for user registration, login, forgot password, reset password with JWT token generation
}
