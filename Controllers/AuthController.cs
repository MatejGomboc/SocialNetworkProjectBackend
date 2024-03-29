﻿using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using SocialNetworkProjectBackend.DbContexts;
using System.ComponentModel.DataAnnotations;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace SocialNetworkProjectBackend.Controllers
{
    [ApiController]
    [Route("api/auth")]
    public class AuthController : ControllerBase
    {
        public class JwtSettings
        {
            public string Key { get; set; } = string.Empty;
            public string Issuer { get; set; } = string.Empty;
            public double AccessTokenLifetimeMinutes { get; set; } = 0.0;
            public double RefreshTokenLifetimeDays { get; set; } = 0.0;
        }

        public class RegisterDto
        {
            [MaxLength(128)]
            [Required(AllowEmptyStrings = false)]
            [DisplayFormat(ConvertEmptyStringToNull = false)]
            public string Username { get; set; } = string.Empty;

            [DataType(DataType.Password)]
            [MaxLength(128)]
            [Required(AllowEmptyStrings = false)]
            [DisplayFormat(ConvertEmptyStringToNull = false)]
            public string Password { get; set; } = string.Empty;

            [DataType(DataType.Password)]
            [MaxLength(128)]
            [Required(AllowEmptyStrings = false)]
            [DisplayFormat(ConvertEmptyStringToNull = false)]
            [Compare(nameof(Password))]
            public string ConfirmPassword { get; set; } = string.Empty;

            [DataType(DataType.EmailAddress)]
            [MaxLength(128)]
            [Required(AllowEmptyStrings = false)]
            [DisplayFormat(ConvertEmptyStringToNull = false)]
            public string EmailAddress { get; set; } = string.Empty;
        }

        public class LoginCredentials
        {
            [MaxLength(128)]
            [Required(AllowEmptyStrings = false)]
            [DisplayFormat(ConvertEmptyStringToNull = false)]
            public string Username { get; set; } = string.Empty;

            [DataType(DataType.Password)]
            [MaxLength(128)]
            [Required(AllowEmptyStrings = false)]
            [DisplayFormat(ConvertEmptyStringToNull = false)]
            public string Password { get; set; } = string.Empty;
        }

        public class LoginResponse
        {
            public string AccessToken { get; set; } = string.Empty;
            public string RefreshToken { get; set; } = string.Empty;
        }

        private readonly JwtSettings _jwtSettings;
        private readonly SocialNetworkProjectDbContext _dbContext;
        private readonly EmailService _emailService;

        private static bool ValidateUsernameFormat(string username)
        {
            if (username.Length < 1)
            {
                return false;
            }

            if (username.Any(char.IsWhiteSpace))
            {
                return false;
            }

            if (username.Any(char.IsSeparator))
            {
                return false;
            }

            if (username.Any(char.IsControl))
            {
                return false;
            }

            if (username.Any(char.IsPunctuation))
            {
                return false;
            }

            if (username.Any(char.IsSymbol))
            {
                return false;
            }

            if (!username.All(char.IsAscii))
            {
                return false;
            }

            return true;
        }

        private static bool ValidatePasswordFormat(string password)
        {
            if (password.Length < 8)
            {
                return false;
            }

            if (password.Any(char.IsWhiteSpace))
            {
                return false;
            }

            if (password.Any(char.IsSeparator))
            {
                return false;
            }

            if (password.Any(char.IsControl))
            {
                return false;
            }

            if (!password.Any(char.IsDigit))
            {
                return false;
            }

            if (!password.Any(char.IsLower))
            {
                return false;
            }

            if (!password.Any(char.IsUpper))
            {
                return false;
            }

            if ((!password.Any(char.IsPunctuation)) && (!password.Any(char.IsSymbol)))
            {
                return false;
            }

            if (!password.All(char.IsAscii))
            {
                return false;
            }

            return true;
        }

        private static string GenerateAccessToken(string username,
            string jwtKey, string jwtIssuer, double lifetimeMinutes)
        {
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey));
            var signingCredentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256Signature);

            var claims = new Claim[]
            {
                new Claim(ClaimTypes.Name, username)
            };

            var token = new JwtSecurityToken(
                issuer: jwtIssuer,
                claims: claims,
                expires: DateTime.UtcNow.AddMinutes(lifetimeMinutes),
                signingCredentials: signingCredentials
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        private static string GenerateRefreshToken()
        {
            var rndNum = new byte[128];
            using RandomNumberGenerator rndNumGen = RandomNumberGenerator.Create();
            rndNumGen.GetBytes(rndNum);
            return Convert.ToBase64String(rndNum);
        }

        public AuthController(IOptions<JwtSettings> jwtSettings,
            SocialNetworkProjectDbContext dbContext, EmailService emailService)
        {
            _jwtSettings = jwtSettings.Value;
            _dbContext = dbContext;
            _emailService = emailService;
        }

        [HttpPost]
        [Route("register")]
        [AllowAnonymous]
        public async Task<IActionResult> Register([FromBody] RegisterDto registerDto)
        {
            try
            {
                if (!ValidateUsernameFormat(registerDto.Username))
                {
                    return BadRequest("Invalid username format.");
                }

                if (_dbContext.Users == null)
                {
                    return Problem(
                        statusCode: 500,
                        title: "Failed to read data from database."
                    );
                }

                SocialNetworkProjectDbContext.User? existingUser;
                try
                {
                    existingUser = await _dbContext.Users.FindAsync(registerDto.Username);
                }
                catch (Exception)
                {
                    return Problem(
                        statusCode: 500,
                        title: "Failed to read data from database."
                    );
                }

                if (existingUser != null)
                {
                    return BadRequest($"User {registerDto.Username} already exists.");
                }

                if (!ValidatePasswordFormat(registerDto.Password))
                {
                    return BadRequest("Invalid password format.");
                }

                if (!await _emailService.SendRegisterConfirmEmailAsync(registerDto.EmailAddress, registerDto.Username, "TODO"))
                {
                    return Problem(
                        statusCode: 500,
                        title: "Failed to send the registration confirmation email."
                    );
                }

                try
                {
                    var newUser = new SocialNetworkProjectDbContext.User
                    {
                        Username = registerDto.Username,
                        PasswordHash = SocialNetworkProjectDbContext.User.HashPassword(registerDto.Password),
                        EmailAddress = registerDto.EmailAddress,
                        EmailAddressConfirmed = false,
                        DateTimeRegistered = DateTime.UtcNow,
                        RefreshTokenHash = "*",
                        DateTimeRefreshTokenCreated = DateTime.MinValue
                    };

                    _dbContext.Users.Add(newUser);
                    await _dbContext.SaveChangesAsync();
                }
                catch (Exception)
                {
                    return Problem(
                        statusCode: 500,
                        title: "Failed to write data to database."
                    );
                }

                return Created(
                    HttpContext.Request.Scheme + "://" + HttpContext.Request.Host + HttpContext.Request.Path,
                    registerDto
                );
            }
            catch (Exception)
            {
                return Problem(
                    statusCode: 500,
                    title: "Internal server error."
                );
            }
        }

        [HttpPatch]
        [Route("login")]
        [AllowAnonymous]
        public async Task<IActionResult> Login([FromBody] LoginCredentials credentials)
        {
            try
            {
                if (_dbContext.Users == null)
                {
                    return Problem(
                        statusCode: 500,
                        title: "Failed to read data from database."
                    );
                }

                SocialNetworkProjectDbContext.User? user;
                try
                {
                    user = await _dbContext.Users.FindAsync(credentials.Username);
                }
                catch (Exception)
                {
                    return Problem(
                        statusCode: 500,
                        title: "Failed to read data from database."
                    );
                }

                if (user == null)
                {
                    return Unauthorized();
                }

                if (!SocialNetworkProjectDbContext.User.VerifyPassword(credentials.Password, user.PasswordHash))
                {
                    return Unauthorized();
                }

                if (!user.EmailAddressConfirmed)
                {
                    return Unauthorized();
                }

                string refreshToken = GenerateRefreshToken();
                user.RefreshTokenHash = SocialNetworkProjectDbContext.User.HashRefreshToken(refreshToken);
                user.DateTimeRefreshTokenCreated = DateTime.UtcNow;

                string accessToken = GenerateAccessToken(
                    credentials.Username,
                    _jwtSettings.Key,
                    _jwtSettings.Issuer,
                    _jwtSettings.AccessTokenLifetimeMinutes
                );

                try
                {
                    _dbContext.Users.Update(user);
                    await _dbContext.SaveChangesAsync();
                }
                catch (Exception)
                {
                    return Problem(
                        statusCode: 500,
                        title: "Failed to write data to database."
                    );
                }

                return Ok(
                    new LoginResponse
                    {
                        AccessToken = accessToken,
                        RefreshToken = refreshToken
                    }
                );
            }
            catch (Exception)
            {
                return Problem(
                    statusCode: 500,
                    title: "Internal server error."
                );
            }
        }

        [HttpPatch]
        [Route("refresh")]
        [AllowAnonymous]
        public async Task<IActionResult> Refresh([FromBody] LoginResponse credentials)
        {
            try
            {
                JwtSecurityToken validatedAccessToken;

                try
                {
                    var jwtHandler = new JwtSecurityTokenHandler();
                    SecurityToken validatedAccessTokenBase;

                    jwtHandler.ValidateToken(
                        credentials.AccessToken,
                        new TokenValidationParameters
                        {
                            RequireSignedTokens = true,
                            ValidateIssuerSigningKey = true,
                            IssuerSigningKey = new SymmetricSecurityKey(
                                Encoding.UTF8.GetBytes(_jwtSettings.Key)
                            ),
                            ValidAlgorithms = new List<string> { SecurityAlgorithms.HmacSha256Signature },

                            ValidateIssuer = true,
                            ValidIssuer = _jwtSettings.Issuer,

                            ValidateAudience = false,

                            RequireExpirationTime = true,
                            ValidateLifetime = false
                        },
                        out validatedAccessTokenBase
                    );

                    validatedAccessToken = (JwtSecurityToken)validatedAccessTokenBase;
                }
                catch (Exception)
                {
                    return Unauthorized();
                }

                Claim? usernameClaim = validatedAccessToken.Claims.FirstOrDefault(e => e.Type == ClaimTypes.Name);
                if (usernameClaim == null)
                {
                    return Unauthorized();
                }

                string username = usernameClaim.Value;

                if (_dbContext.Users == null)
                {
                    return Problem(
                        statusCode: 500,
                        title: "Failed to read data from database."
                    );
                }

                SocialNetworkProjectDbContext.User? user;
                try
                {
                    user = await _dbContext.Users.FindAsync(username);
                }
                catch (Exception)
                {
                    return Problem(
                        statusCode: 500,
                        title: "Failed to read data from database."
                    );
                }

                if (user == null)
                {
                    return Unauthorized();
                }

                if (!SocialNetworkProjectDbContext.User.VerifyRefreshToken(credentials.RefreshToken, user.RefreshTokenHash))
                {
                    return Unauthorized();
                }

                if (DateTime.UtcNow > user.DateTimeRefreshTokenCreated.AddDays(_jwtSettings.RefreshTokenLifetimeDays))
                {
                    return Unauthorized();
                }

                string newRefreshToken = GenerateRefreshToken();
                user.RefreshTokenHash = SocialNetworkProjectDbContext.User.HashRefreshToken(newRefreshToken);
                user.DateTimeRefreshTokenCreated = DateTime.UtcNow;

                string newAccessToken = GenerateAccessToken(
                    username,
                    _jwtSettings.Key,
                    _jwtSettings.Issuer,
                    _jwtSettings.AccessTokenLifetimeMinutes
                );

                try
                {
                    _dbContext.Users.Update(user);
                    await _dbContext.SaveChangesAsync();
                }
                catch (Exception)
                {
                    return Problem(
                        statusCode: 500,
                        title: "Failed to write data to database."
                    );
                }

                return Ok(
                    new LoginResponse
                    {
                        AccessToken = newAccessToken,
                        RefreshToken = newRefreshToken
                    }
                );
            }
            catch (Exception)
            {
                return Problem(
                    statusCode: 500,
                    title: "Internal server error."
                );
            }
        }

        [HttpPatch]
        [Route("logout")]
        [Authorize]
        public async Task<IActionResult> Logout()
        {
            try
            {
                string? username = HttpContext.User.FindFirstValue(ClaimTypes.Name);
                if (username == null)
                {
                    return Unauthorized();
                }

                if (_dbContext.Users == null)
                {
                    return Problem(
                        statusCode: 500,
                        title: "Failed to read data from database."
                    );
                }

                SocialNetworkProjectDbContext.User? user;
                try
                {
                    user = await _dbContext.Users.FindAsync(username);
                }
                catch (Exception)
                {
                    return Problem(
                        statusCode: 500,
                        title: "Failed to read data from database."
                    );
                }

                if (user == null)
                {
                    return Unauthorized();
                }

                user.RefreshTokenHash = "*";
                user.DateTimeRefreshTokenCreated = DateTime.MinValue;

                try
                {
                    _dbContext.Users.Update(user);
                    await _dbContext.SaveChangesAsync();
                }
                catch (Exception)
                {
                    return Problem(
                        statusCode: 500,
                        title: "Failed to write data to database."
                    );
                }

                return Ok();
            }
            catch (Exception)
            {
                return Problem(
                    statusCode: 500,
                    title: "Internal server error."
                );
            }
        }

        [HttpDelete]
        [Route("unregister")]
        [Authorize]
        public async Task<IActionResult> Unregister()
        {
            try
            {
                string? username = HttpContext.User.FindFirstValue(ClaimTypes.Name);
                if (username == null)
                {
                    return Unauthorized();
                }

                if (_dbContext.Users == null)
                {
                    return Problem(
                        statusCode: 500,
                        title: "Failed to read data from database."
                    );
                }

                SocialNetworkProjectDbContext.User? user;
                try
                {
                    user = await _dbContext.Users.FindAsync(username);
                }
                catch (Exception)
                {
                    return Problem(
                        statusCode: 500,
                        title: "Failed to read data from database."
                    );
                }

                if (user == null)
                {
                    return Unauthorized();
                }

                try
                {
                    _dbContext.Users.Remove(user);
                    await _dbContext.SaveChangesAsync();
                }
                catch (Exception)
                {
                    return Problem(
                        statusCode: 500,
                        title: "Failed to write data to database."
                    );
                }

                return Ok();
            }
            catch (Exception)
            {
                return Problem(
                    statusCode: 500,
                    title: "Internal server error."
                );
            }
        }
    }
}