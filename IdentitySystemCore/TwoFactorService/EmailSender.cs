using System;
using System.Threading.Tasks;
using Microsoft.Extensions.Options;
using SendGrid;
using SendGrid.Helpers.Mail;

namespace IdentitySystemCore.TwoFactorService
{
    public class EmailSender
    {
        private readonly TwoFactorOptions _twoFactorOptions;
        private readonly TwoFactorService _twoFactorService;

        public EmailSender(IOptions<TwoFactorOptions> options, TwoFactorService twoFactorService)
        {
            _twoFactorOptions = options.Value;
            _twoFactorService = twoFactorService;
        }

        public string Send(string emailAddress)
        {
            string code = _twoFactorService.GetCodeVerification().ToString();
            Execute(emailAddress, code).Wait();
            return code;
        }

        private async Task Execute(string email, string code)
        {
            var client = new SendGridClient(_twoFactorOptions.SendGrid_API_KEY);
            var from = new EmailAddress("kulakberkay15@gmail.com");
            var subject = "İki Adımlı Kimlik Doğrulama Kodunuz";
            var to = new EmailAddress(email);
            var htmlContent = $"<h2>Siteye Giriş Yapabilmek için Doğrulama Kodunuz Aşağıdadır.</h2> <h3>Kodunuz: {code}</h3>";
            var msg = MailHelper.CreateSingleEmail(from, to, subject, null, htmlContent);
            var response = await client.SendEmailAsync(msg);
        }
    }
}
