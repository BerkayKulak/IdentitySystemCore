using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;
using IdentitySystemCore.Enums;

namespace IdentitySystemCore.ViewModels
{
    public class AuthenticatorViewModel
    {
        public string SharedKey { get; set; }
        public string AuthenticatorUri { get; set; }

        [Display(Name = "Doğrulama Kodunuz")]
        [Required(ErrorMessage = "Doğrulama Kodu Gereklidir")]
        public string VerificationCode { get; set; }
        [Display(Name = "İki Adımlı Kimlik Doğrulama Tipi")]
        public TwoFactor TwoFactorType { get; set; }

    }
}
