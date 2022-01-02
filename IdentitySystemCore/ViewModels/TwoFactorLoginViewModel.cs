using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;
using IdentitySystemCore.Enums;

namespace IdentitySystemCore.ViewModels
{
    public class TwoFactorLoginViewModel
    {
        [Display(Name = "Doğrulama Kodunuz")]
        [Required(ErrorMessage = "Doğrulama Kodu Boş Olamaz")]
        [StringLength(8,ErrorMessage = "Doğrulama Kodunuz En Fazla 8 haneli olabilir.")]
        public string VerificationCode { get; set; }

        public bool isRememberMe { get; set; }

        public bool isRecoverCode { get; set; }

        public TwoFactor TwoFactorType { get; set; }

    }
}
