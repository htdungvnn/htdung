namespace AuthApi.DTOs;

public record ChangePasswordDto(string OldPassword, string NewPassword);
public record LoginDto(string Email, string Password);
public record RegisterDto(string FullName, string Email, string Password);

public record UpdateRoleDto(string Role); // "Admin", "User"
