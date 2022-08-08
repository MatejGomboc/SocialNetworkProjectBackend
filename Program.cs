using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using SocialNetworkProjectBackend;
using SocialNetworkProjectBackend.Controllers;
using SocialNetworkProjectBackend.DbContexts;
using Swashbuckle.AspNetCore.Filters;
using System.Text;

WebApplicationBuilder builder = WebApplication.CreateBuilder(args);

var settings = new Dictionary<string, string>
{
    { "DatabaseConnectionString", Environment.GetEnvironmentVariable("DATABASE_CONNECTION_STRING") ??
        builder.Configuration.GetSection("Secrets:DatabaseConnectionString").Value },

    { "Jwt:Key", Environment.GetEnvironmentVariable("JWT_KEY") ??
        builder.Configuration.GetSection("Secrets:JwtKey").Value },

    { "Jwt:Issuer", builder.Configuration.GetSection("Jwt:Issuer").Value },
    { "Jwt:AccessTokenLifetimeMinutes", builder.Configuration.GetSection("Jwt:AccessTokenLifetimeMinutes").Value },
    { "Jwt:RefreshTokenLifetimeDays", builder.Configuration.GetSection("Jwt:RefreshTokenLifetimeDays").Value },

    { "Mailing:SendgridApiKey", Environment.GetEnvironmentVariable("SENDGRID_API_KEY") ??
        builder.Configuration.GetSection("Secrets:SendgridApiKey").Value },

    { "Mailing:FromAddress", Environment.GetEnvironmentVariable("FROM_EMAIL_ADDRESS") ??
        builder.Configuration.GetSection("Secrets:FromEmailAddress").Value },

    { "Mailing:FromName", builder.Configuration.GetSection("Mailing:FromName").Value },

    { "Cors:FrontendUrl", Environment.GetEnvironmentVariable("FRONTEND_URL") ??
        builder.Configuration.GetSection("Secrets:FrontendUrl").Value }
};

var configurationBuilder = new ConfigurationBuilder();
configurationBuilder.AddInMemoryCollection(settings);
IConfiguration configuration = configurationBuilder.Build();

builder.Services.Configure<AuthController.JwtSettings>(configuration.GetSection("Jwt"));
builder.Services.Configure<EmailService.Settings>(configuration.GetSection("Mailing"));

builder.Services.AddControllers();

builder.Services.AddDbContext<SocialNetworkProjectDbContext>(
    options => options.UseNpgsql(configuration.GetSection("DatabaseConnectionString").Value),
    ServiceLifetime.Scoped
);

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme).AddJwtBearer(
    options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            RequireSignedTokens = true,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(
                Encoding.UTF8.GetBytes(configuration.GetSection("Jwt:Key").Value)
            ),
            ValidAlgorithms = new List<string> { SecurityAlgorithms.HmacSha256Signature },

            ValidateIssuer = true,
            ValidIssuer = configuration.GetSection("Jwt:Issuer").Value,

            ValidateAudience = false,

            RequireExpirationTime = true,
            ValidateLifetime = true,
            ClockSkew = TimeSpan.Zero,

            ValidTypes = new List<string> { "JWT" }
        };
    }
);

builder.Services.AddEndpointsApiExplorer();

builder.Services.AddSwaggerGen(
    options =>
    {
        options.AddSecurityDefinition("oauth2", new OpenApiSecurityScheme
        {
            In = ParameterLocation.Header,
            Name = "Authorization",
            Type = SecuritySchemeType.ApiKey,
            Scheme = "Bearer",
            Description = "bearer {access_token}"
        });

        options.OperationFilter<SecurityRequirementsOperationFilter>();
    }
);

builder.Services.AddCors(options =>
    {
        options.AddDefaultPolicy(builder =>
            {
                builder.AllowAnyMethod().AllowAnyHeader().DisallowCredentials()
                    .WithOrigins(configuration.GetSection("Cors:FrontendUrl").Value);
            }
        );
    }
);

builder.Services.AddSingleton<EmailService>();

WebApplication app = builder.Build();

app.UseSwagger();
app.UseSwaggerUI();
app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();
app.UseCors();
app.Run();