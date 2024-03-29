﻿using Isopoh.Cryptography.Argon2;
using Microsoft.EntityFrameworkCore;
using System.ComponentModel.DataAnnotations;

namespace SocialNetworkProjectBackend.DbContexts
{
    public class SocialNetworkProjectDbContext : DbContext
    {
        public class User
        {
            public static string HashPassword(string password)
            {
                return Argon2.Hash(password);
            }

            public static bool VerifyPassword(string password, string passwordHash)
            {
                return Argon2.Verify(passwordHash, password);
            }

            public static string HashRefreshToken(string refreshToken)
            {
                return Argon2.Hash(refreshToken);
            }

            public static bool VerifyRefreshToken(string refreshToken, string refreshTokenHash)
            {
                return Argon2.Verify(refreshTokenHash, refreshToken);
            }

            [Key]
            [MaxLength(128)]
            [Required(AllowEmptyStrings = false)]
            [DisplayFormat(ConvertEmptyStringToNull = false)]
            public string Username { get; set; } = string.Empty;

            [Required(AllowEmptyStrings = false)]
            [DisplayFormat(ConvertEmptyStringToNull = false)]
            public string PasswordHash { get; set; } = string.Empty;

            [DataType(DataType.EmailAddress)]
            [MaxLength(128)]
            [Required(AllowEmptyStrings = false)]
            [DisplayFormat(ConvertEmptyStringToNull = false)]
            public string EmailAddress { get; set; } = string.Empty;

            [Required]
            public bool EmailAddressConfirmed { get; set; } = false;

            [DataType(DataType.DateTime)]
            [Required]
            public DateTime DateTimeRegistered { get; set; } = DateTime.UnixEpoch;

            [Required(AllowEmptyStrings = false)]
            [DisplayFormat(ConvertEmptyStringToNull = false)]
            public string RefreshTokenHash { get; set; } = string.Empty;

            [DataType(DataType.DateTime)]
            [Required]
            public DateTime DateTimeRefreshTokenCreated { get; set; } = DateTime.UnixEpoch;
        }

        public SocialNetworkProjectDbContext(DbContextOptions<SocialNetworkProjectDbContext> options) :
            base(options)
        {
        }

        public DbSet<User>? Users { get; set; }
    }
}