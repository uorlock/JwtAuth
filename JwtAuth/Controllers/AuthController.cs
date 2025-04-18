using System.Security.Claims;
using JwtAuth.Entities;
using JwtAuth.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
<<<<<<< HEAD
using JwtAuth.Services;
=======
using System.Security.Cryptography;
using System.Text;
//using System.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
>>>>>>> 3a7cfc9eb15e41828edbb10daac3f6eb914ad0d8

namespace JwtAuth.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
<<<<<<< HEAD
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
=======
    public class AuthController(IConfiguration configuration) : ControllerBase
    {
        public static User user = new User();

        [HttpPost("register")]
        public ActionResult<User> Register(UserDto request)
        {
            var hashedPassword = new PasswordHasher<User>()
                .HashPassword(user, request.Password);

            user.Username = request.Username;
            user.PasswordHash = hashedPassword;


            //// Validate the userDto object
            //// Here you would typically save the user to a database
            //// For this example, we'll just return the user object
            //var user = new User
            //{
            //    Username = userDto.Username,
            //    PasswordHash = BCrypt.Net.BCrypt.HashPassword(userDto.PasswordHash)
            //};
>>>>>>> 3a7cfc9eb15e41828edbb10daac3f6eb914ad0d8
            return Ok(user);
        }

        [HttpPost("login")]
<<<<<<< HEAD
        public async Task<ActionResult<string>> Login(UserDto request)
        {
            var token = await authService.LoginAsync(request);
            if (token is null)
                return BadRequest("Invalid credentials.");

            return Ok(token);
        }
=======
        public ActionResult<string> Login(UserDto request)
        {
            if (user.Username != request.Username)
            {
                return BadRequest("User not found");
            }

            if (new PasswordHasher<User>().VerifyHashedPassword(user, user.PasswordHash, request.Password)
                == PasswordVerificationResult.Failed)
            {
                return BadRequest("Wrong password.");
            }

            // Generate JWT token here
            string token = CreateToken(user);

            return Ok(token);
        }

        private string CreateToken(User user)
        {
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, user.Username)
            };

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(configuration.GetValue<string>("AppSettings:Token")!));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha512);
            var tokenDescriptor = new JwtSecurityToken(
                issuer: configuration.GetValue<string>("appSettings:Issuer"),
                audience: configuration.GetValue<string>("appSettings:Audience"),
                claims: claims,
                expires: DateTime.UtcNow.AddDays(1),
                signingCredentials: creds
                );


            return new JwtSecurityTokenHandler().WriteToken(tokenDescriptor);
        }



>>>>>>> 3a7cfc9eb15e41828edbb10daac3f6eb914ad0d8
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
