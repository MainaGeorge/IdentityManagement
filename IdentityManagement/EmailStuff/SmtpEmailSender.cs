using MailKit.Net.Smtp;
using MailKit.Security;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using MimeKit;
using System;
using System.Threading.Tasks;
using MimeKit.Text;

namespace IdentityManagement.EmailStuff
{
    public class SmtpEmailSender : IEmailSender
    {
        private readonly IWebHostEnvironment _environment;
        private readonly SmtpSettings _smtpSettings;
        public SmtpEmailSender(IOptions<SmtpSettings> smtpSettings, IWebHostEnvironment environment)
        {
            _environment = environment;
            _smtpSettings = smtpSettings.Value;
        }
        public async Task SendEmailAsync(string email, string subject, string htmlMessage)
        {
            try
            {
                var message = SetMessage(email, subject, htmlMessage);
                using var client = new SmtpClient();

                if (_environment.IsDevelopment())
                    await client.ConnectAsync(_smtpSettings.Server, _smtpSettings.Port, SecureSocketOptions.StartTls);

                else
                    await client.ConnectAsync(_smtpSettings.Server);

                await client.AuthenticateAsync(_smtpSettings.Username, _smtpSettings.Password);
                await client.SendAsync(message);
                await client.DisconnectAsync(true);

            }
            catch (Exception e)
            {
                throw new InvalidOperationException(e.Message);
            }
        }

        private MimeMessage SetMessage(string email, string subject, string htmlMessage)
        {
            var message = new MimeMessage();
            message.From.Add(new MailboxAddress(_smtpSettings.SenderName, _smtpSettings.SenderEmail));
            message.To.Add(new MailboxAddress(email));
            message.Subject = subject;
            message.Body = new TextPart(TextFormat.Html)
            {
                Text = htmlMessage
            };

            return message;
        }
    }
}
