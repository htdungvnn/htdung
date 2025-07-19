using System.Net;
using System.Net.Mail;

namespace AuthApi.Services;

public class EmailService
{
    private readonly IConfiguration _config;

    public EmailService(IConfiguration config)
    {
        _config = config;
    }

    public async Task SendVerificationEmailAsync(string toEmail, string verificationCode)
    {
        var smtpHost = _config["Email:SmtpHost"];
        var smtpPort = int.Parse(_config["Email:SmtpPort"]);
        var smtpUser = _config["Email:SmtpUser"];
        var smtpPass = _config["Email:SmtpPass"];
        var fromEmail = _config["Email:From"];

        var verifyUrl = $"{_config["App:BaseUrl"]}/api/auth/verify?email={WebUtility.UrlEncode(toEmail)}&code={verificationCode}";

        var message = new MailMessage(fromEmail, toEmail)
        {
            Subject = "Verify your email",
            IsBodyHtml = true,
            Body = $"<p>Click the link to verify your email:</p><p><a href=\"{verifyUrl}\">{verifyUrl}</a></p>"
        };

        using var client = new SmtpClient(smtpHost, smtpPort)
        {
            Credentials = new NetworkCredential(smtpUser, smtpPass),
            EnableSsl = true
        };

        await client.SendMailAsync(message);
    }
}