using System.Security.Claims;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using AuthApi.Data;
using AuthApi.DTOs;
using AuthApi.Models;
using AuthApi.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddDbContext<AppDbContext>(opt =>
    opt.UseNpgsql(builder.Configuration.GetConnectionString("Default")));

builder.Services.AddScoped<AuthService>();
builder.Services.AddScoped<EmailService>();

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(opt =>
    {
        var key = builder.Configuration["Jwt:Key"]!;
        opt.TokenValidationParameters = new()
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = builder.Configuration["Jwt:Issuer"],
            ValidAudience = builder.Configuration["Jwt:Audience"],
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(key))
        };
    });

builder.Services.AddAuthorization();

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(options =>
{
    // Enable JWT in Swagger
    options.AddSecurityDefinition("Bearer", new Microsoft.OpenApi.Models.OpenApiSecurityScheme
    {
        Name = "Authorization",
        Type = Microsoft.OpenApi.Models.SecuritySchemeType.ApiKey,
        Scheme = "Bearer",
        BearerFormat = "JWT",
        In = Microsoft.OpenApi.Models.ParameterLocation.Header,
        Description = "Enter: Bearer <your JWT token>"
    });

    options.AddSecurityRequirement(new Microsoft.OpenApi.Models.OpenApiSecurityRequirement
    {
        {
            new Microsoft.OpenApi.Models.OpenApiSecurityScheme
            {
                Reference = new Microsoft.OpenApi.Models.OpenApiReference
                {
                    Type = Microsoft.OpenApi.Models.ReferenceType.SecurityScheme,
                    Id = "Bearer"
                }
            },
            new string[] {}
        }
    });
});

var app = builder.Build();
app.UseAuthentication();
app.UseAuthorization();

app.MapPost("/api/auth/register", async (RegisterDto dto, AuthService service) =>
{
    try { return Results.Ok(new { token = await service.RegisterAsync(dto) }); }
    catch (Exception ex) { return Results.BadRequest(new { error = ex.Message }); }
});
app.MapPost("/api/auth/login", async (LoginDto dto, AuthService service) =>
{
    try { return Results.Ok(new { token = await service.LoginAsync(dto) }); }
    catch (Exception ex) { return Results.BadRequest(new { error = ex.Message }); }
});
app.MapGet("/api/auth/me", [Authorize] (ClaimsPrincipal user) =>
{
    var id = user.FindFirst(ClaimTypes.NameIdentifier)?.Value;
    var email = user.FindFirst(ClaimTypes.Email)?.Value;
    var role = user.FindFirst(ClaimTypes.Role)?.Value;

    return Results.Ok(new { id, email, role });
});


app.MapPut("/api/auth/change-password", [Authorize] async (
    ChangePasswordDto dto,
    ClaimsPrincipal user,
    AuthService service) =>
{
    var userId = user.FindFirst(ClaimTypes.NameIdentifier)?.Value;
    if (userId is null) return Results.Unauthorized();

    try
    {
        await service.ChangePasswordAsync(Guid.Parse(userId), dto);
        return Results.Ok("Password changed.");
    }
    catch (Exception ex)
    {
        return Results.BadRequest(new { error = ex.Message });
    }
});
app.MapGet("/api/secure", [Authorize(Roles = "Admin")] () =>
{
    return Results.Ok("You are an Admin!");
});
app.MapGet("/api/users", [Authorize(Roles = "Admin")] async (AppDbContext db) =>
{
    var users = await db.Users
        .Select(u => new { u.Id, u.FullName, u.Email, u.Role })
        .ToListAsync();

    return Results.Ok(users);
});
app.MapGet("/api/users/{id:guid}", [Authorize(Roles = "Admin")] async (Guid id, AppDbContext db) =>
{
    var user = await db.Users.FindAsync(id);
    return user is null
        ? Results.NotFound()
        : Results.Ok(new { user.Id, user.FullName, user.Email, user.Role });
});


app.MapPut("/api/users/{id:guid}/role", [Authorize(Roles = "User")] async (
    Guid id,
    UpdateRoleDto dto,
    AppDbContext db) =>
{
    var user = await db.Users.FindAsync(id);
    if (user is null) return Results.NotFound();

    if (!Enum.TryParse<Role>(dto.Role, out var newRole))
        return Results.BadRequest("Invalid role.");

    user.Role = newRole;
    await db.SaveChangesAsync();

    return Results.Ok(new { message = "Role updated." });
});
app.MapDelete("/api/users/{id:guid}", [Authorize(Roles = "Admin")] async (Guid id, AppDbContext db) =>
{
    var user = await db.Users.FindAsync(id);
    if (user is null) return Results.NotFound();

    db.Users.Remove(user);
    await db.SaveChangesAsync();

    return Results.Ok(new { message = "User deleted." });
});
app.MapGet("/api/auth/verify", async (
    [FromQuery] string email,
    [FromQuery] string code,
    AppDbContext db) =>
{
    var user = await db.Users.FirstOrDefaultAsync(u => u.Email == email);
    if (user is null) return Results.NotFound("User not found.");

    if (user.IsVerified)
        return Results.Ok("Account already verified.");

    if (user.VerificationCode != code)
        return Results.BadRequest("Invalid verification code.");

    user.IsVerified = true;
    user.VerificationCode = null;
    await db.SaveChangesAsync();

    return Results.Ok("Your email has been successfully verified!");
});

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
    db.Database.Migrate(); // ✅ Auto-create tables
}

app.Run();