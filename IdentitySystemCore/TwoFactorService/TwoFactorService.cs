using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Encodings.Web;
using System.Threading.Tasks;

namespace IdentitySystemCore.TwoFactorService
{
    public class TwoFactorService
    {
        private readonly UrlEncoder _urlEncoder;

        public TwoFactorService(UrlEncoder urlEncoder)
        {
            _urlEncoder = urlEncoder;
        }

        public int GetCodeVerification()
        {
            Random random = new Random();
            return random.Next(1000, 9999);
        }

        public string GenerateQrCodeUri(string email, string unformattedKey)
        {
            const string format = "otpauth://totp/{0}:{1}?secret={2}&issuer={0}&digits=6";

            return string.Format(format,
                _urlEncoder.Encode("www.bidibidi.com"), _urlEncoder.Encode(email), unformattedKey);

        }
    }
}
