namespace AuthApi.Models;

public enum Role { Admin, User }

public class User
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public string FullName { get; set; } = string.Empty;
    public string Email { get; set; } = string.Empty;
    public byte[] PasswordHash { get; set; }
    public byte[] PasswordSalt { get; set; }
    public Role Role { get; set; } = Role.User;
    
    public bool IsVerified { get; set; } = false;
    public string? VerificationCode { get; set; }
}