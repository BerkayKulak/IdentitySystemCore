using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using IdentitySystemCore.Models;
using Microsoft.AspNetCore.Identity;

namespace IdentitySystemCore.CustomValidator
{
    public class CustomPasswordValidator : IPasswordValidator<AppUser>
    {
        public Task<IdentityResult> ValidateAsync(UserManager<AppUser> manager, AppUser user, string password)
        {
            List<IdentityError> errors = new List<IdentityError>();
            

            if (password.ToLower().Contains(user.UserName.ToLower()))
            {
                // kullanıcının email adresi bir username içermiyorsa bu hatayı göster.
                if (!user.Email.Contains(user.UserName))
                {
                    errors.Add(new IdentityError()
                    {
                        Code = "PasswordContainsUserName",
                        Description = "şifre alanı kullanıcı adı içeremez"

                    });
                }


            }

            if (password.ToLower().Contains("1234"))
            {
                errors.Add(new IdentityError()
                {
                    Code = "PasswordContains1234",
                    Description = "şifre alanı ardışık sayı içeremez"

                });
            }

            if (password.ToLower().Contains(user.Email.ToLower()))
            {
                errors.Add(new IdentityError()
                {
                    Code = "PasswordContainsEmail",
                    Description = "şifre alanı email adresini içeremez"

                });
            }


            if (errors.Count == 0)
            {
                return Task.FromResult(IdentityResult.Success);
            }

            else
            {
                // failed başarısız demek ama bizden bir Identity Error isminde bir array istiyor
                return Task.FromResult(IdentityResult.Failed(errors.ToArray()));
            }



        }
    }
}
