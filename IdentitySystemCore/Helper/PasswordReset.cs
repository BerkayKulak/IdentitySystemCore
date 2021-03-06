using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Mail;
using System.Threading.Tasks;

namespace IdentitySystemCore.Helper
{
    public static class PasswordReset
    {
        public static void PasswordResetSendEmail(string link,string email)
        {
            MailMessage mail = new MailMessage();

            // bunu host firmanızdan öğrenilir
            SmtpClient smtpClient = new SmtpClient("smtp.gmail.com");

            // email kulakberkay15@gmail.com den  beko_468@hotmail.com ' e bir tane email gelecek
            mail.From = new MailAddress("kulakberkay15@gmail.com");

            // kime gidicek email burada belirtiyoruz
            mail.To.Add(email);
            mail.Subject = $"www.bıdıbıdı.com::Şifre Sıfırlama";
            mail.Body = "<h2>Şifrenizi yenilemek için lütfen aşağıdaki linke tıklayınız.</h2><hr/>";
            mail.Body += $"<a href = '{link}'> şifre yenileme linki </a>";
            mail.IsBodyHtml = true;
            smtpClient.Port = 587;
            smtpClient.EnableSsl = true;
            smtpClient.Credentials = new System.Net.NetworkCredential("kulakberkay15@gmail.com", "43795164825Fb");
            smtpClient.Send(mail);

        }
    }
}
