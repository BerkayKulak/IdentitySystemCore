using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace IdentitySystemCore.Enums
{
    public enum TwoFactor
    {
        [Display(Name = "Hiç Biri")]
        None=0,
        [Display(Name = "Telefon İle Kimlik Doğrulama")]
        Phone = 1,
        [Display(Name = "Email ile Kimlik Doğrulama")]
        Email = 2,
        [Display(Name = "Microsoft/Google Authtenticator İle Kimlik Doğrulama")]
        MicrosoftGoogle =3
    }
}
