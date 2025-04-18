using System.Security.Claims;
using JwtAuth.Entities;
using JwtAuth.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using JwtAuth.Services;

namespace JwtAuth.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController(IAuthService authService) : ControllerBase
    {
        [HttpPost("register")]
        public async Task<ActionResult<User>> Register(UserDto request)
        {
            var user = await authService.RegisterAsync(request);
            if (user is null)
            {
                return BadRequest("User already exists.");
            }
            return Ok(user);
        }

        [HttpPost("login")]
        public async Task<ActionResult<string>> Login(UserDto request)
        {
            var token = await authService.LoginAsync(request);
            if (token is null)
                return BadRequest("Invalid credentials.");

            return Ok(token);
        }
        //public ActionResult<string> Login(UserDto request)
        //{
        //    if (user.Username != request.Username)
        //    {
        //        return BadRequest("User not found");
        //    }
        //    var result = new PasswordHasher<User>()
        //        .VerifyHashedPassword(user, user.PasswordHash, request.Password);
        //    if (result == PasswordVerificationResult.Failed)
        //    {
        //        return BadRequest("Wrong password");
        //    }
        //    // Generate JWT token here
        //    // For this example, we'll just return a simple string
        //    return Ok("Token");
    }
}
