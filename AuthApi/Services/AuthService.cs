using AuthApi.Data;
using AuthApi.DTOs;
using AuthApi.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace AuthApi.Services;

public class AuthService
{
    private readonly AppDbContext _db;
    private readonly IConfiguration _config;
    private readonly EmailService _emailService;

    public AuthService(AppDbContext db, IConfiguration config, EmailService emailService)
    {
        _db = db;
        _config = config;
        _emailService = emailService;
    }

    public async Task<string> RegisterAsync(RegisterDto dto)
    {
        if (await _db.Users.AnyAsync(u => u.Email == dto.Email))
            throw new Exception("Email already registered.");

        CreatePasswordHash(dto.Password, out var hash, out var salt);

        var verificationCode = new Random().Next(100000, 999999).ToString(); // 6-digit

        var user = new User
        {
            FullName = dto.FullName,
            Email = dto.Email,
            PasswordHash = hash,
            PasswordSalt = salt,
            Role = Role.User,
            VerificationCode = verificationCode,
            IsVerified = false
        };

        _db.Users.Add(user);
        await _db.SaveChangesAsync();

        await _emailService.SendVerificationEmailAsync(dto.Email, verificationCode);

        return GenerateJwtToken(user); // You can skip token here if email verification is mandatory first
    }

    public async Task<string> LoginAsync(LoginDto dto)
    {
        var user = await _db.Users.FirstOrDefaultAsync(u => u.Email == dto.Email)
                   ?? throw new Exception("User not found");

        if (!VerifyPassword(dto.Password, user.PasswordHash, user.PasswordSalt))
            throw new Exception("Invalid credentials");

        if (!user.IsVerified)
            throw new Exception("Email is not verified.");

        return GenerateJwtToken(user);
    }

    public async Task ChangePasswordAsync(Guid userId, ChangePasswordDto dto)
    {
        var user = await _db.Users.FindAsync(userId)
                   ?? throw new Exception("User not found");

        if (!VerifyPassword(dto.OldPassword, user.PasswordHash, user.PasswordSalt))
            throw new Exception("Old password is incorrect");

        CreatePasswordHash(dto.NewPassword, out var newHash, out var newSalt);

        user.PasswordHash = newHash;
        user.PasswordSalt = newSalt;

        await _db.SaveChangesAsync();
    }

    private string GenerateJwtToken(User user)
    {
        var claims = new[]
        {
            new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
            new Claim(ClaimTypes.Email, user.Email),
            new Claim(ClaimTypes.Role, user.Role.ToString())
        };

        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["Jwt:Key"]!));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        var token = new JwtSecurityToken(
            issuer: _config["Jwt:Issuer"],
            audience: _config["Jwt:Audience"],
            claims: claims,
            expires: DateTime.UtcNow.AddDays(7),
            signingCredentials: creds
        );

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    private void CreatePasswordHash(string password, out byte[] hash, out byte[] salt)
    {
        using var hmac = new HMACSHA512();
        salt = hmac.Key;
        hash = hmac.ComputeHash(Encoding.UTF8.GetBytes(password));
    }

    private bool VerifyPassword(string password, byte[] hash, byte[] salt)
    {
        using var hmac = new HMACSHA512(salt);
        var computed = hmac.ComputeHash(Encoding.UTF8.GetBytes(password));
        return computed.SequenceEqual(hash);
    }
}