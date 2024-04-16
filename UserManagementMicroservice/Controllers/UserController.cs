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
    private async Task<IActionResult> RegisterUser<T>(T model, string role, string successMessage, string failureMessage)
    {
        // Validation logic for the model here

        UserEntity user = null;

        if (model is AdminRegistrationModel adminModel)
        {
            user = new UserEntity
            {
                FirstName = adminModel.FirstName,
                LastName = adminModel.LastName,
                Email = adminModel.Email,
                Password = adminModel.Password,
                Role = role // Assigning the role
            };
        }
        else if (model is PatientRegistrationModel patientModel)
        {
            user = new UserEntity
            {
                FirstName = patientModel.FirstName,
                LastName = patientModel.LastName,
                Email = patientModel.Email,
                Password = patientModel.Password,
                Role = role // Assigning the role
            };
        }
        // Add similar logic for other registration models

        if (user == null)
        {
            return BadRequest("Invalid registration model type.");
        }

        var result = await _userManagementServices.RegisterUser(user);
        if (result)
            return Ok(successMessage);
        return BadRequest(failureMessage);
    }



    [HttpPost("register/admin")]
    public async Task<IActionResult> RegisterAdmin(AdminRegistrationModel model)
    {
        // Specify UserEntity as the type argument for RegisterUser
        return await RegisterUser(model, "Admin", "Admin registered successfully", "Admin registration failed");
    }

    [HttpPost("register/patient")]
    public async Task<IActionResult> RegisterPatient(PatientRegistrationModel model)
    {
        // Specify UserEntity as the type argument for RegisterUser
        return await RegisterUser(model, "Patient", "Patient registered successfully", "Patient registration failed");
    }

    [HttpPost("register/doctor")]
    public async Task<IActionResult> RegisterDoctor(DoctorRegistrationModel model)
    {
        // Specify UserEntity as the type argument for RegisterUser
        return await RegisterUser(model, "Doctor", "Doctor registered successfully", "Doctor registration failed");
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
