﻿using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using IdentitySystemCore.Models;
using IdentitySystemCore.ViewModels;
using Mapster;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;

namespace IdentitySystemCore.Controllers
{

    //[Authorize]// membercontrollere sadece üyeler erişecek.
    public class MemberController : Controller
    {
        public UserManager<AppUser> userManager { get; }
        public SignInManager<AppUser> signInManager { get; }
        public MemberController(UserManager<AppUser> userManager, SignInManager<AppUser> signInManager)
        {
            this.userManager = userManager;
            this.signInManager = signInManager;
        }


        public IActionResult Index()
        {
            // kullanıcı bir siteye geldiği zaman, üye de olsa olmasada user classı oluşturur
            // bir tane kimliği oluşur, eğer kullanıcı giriş yapmamışsa isauthenticate false olur.
            // boş bir kimlik oluşur. login olursa biz name,usernama gibi alanları yakalayabiliriz.
            //User.Identity.


            AppUser user = userManager.FindByNameAsync(User.Identity.Name).Result;
            // userin içindeki propertylerden UserViewModel içerisindeki Propertyler ile eşleşenleri
            // userViewModel'e aktaracak
            UserViewModel userViewModel = user.Adapt<UserViewModel>();

            //UserViewModel userViewModel = new UserViewModel();
            //userViewModel.UserName = user.UserName;


            return View(userViewModel);
        }

        public IActionResult UserEdit()
        {
            // UserViewModel, AppUser'in kullanıcıya yansıyan tarafıydı
            AppUser user = userManager.FindByNameAsync(User.Identity.Name).Result;

            UserViewModel userViewModel = user.Adapt<UserViewModel>();

            return View(userViewModel);// kullanıcı bilgileri güncellicek bu yüzden UserViewModel'i dolu olarak gönderiyorum.
        }

        public IActionResult PasswordChange()
        {
            return View();
        }

        [HttpPost]
        public IActionResult PasswordChange(PasswordChangeViewModel passwordChangeViewModel)
        {

            if (ModelState.IsValid)
            {
                // burdaki name değeri Cookie bilgisinden okuyor.
                AppUser user = userManager.FindByNameAsync(User.Identity.Name).Result;


                // eski şifresi doğru mu ilk bunu kontrol edelim.
                bool exist = userManager.CheckPasswordAsync(user, passwordChangeViewModel.PasswordOld).Result;

                // şifre doğruysa yani şifre varsa
                if (exist)
                {
                    IdentityResult result = userManager.ChangePasswordAsync(user, passwordChangeViewModel.PasswordOld, passwordChangeViewModel.PasswordNew).Result;

                    // kullanıcı şifresi doğruysa direk Index ' e yönlendirebiliriz.
                    // ya da şifreniz değiştirildi diyebiliriz. biz böyle yapcaz.
                    if (result.Succeeded)
                    {
                        userManager.UpdateSecurityStampAsync(user);

                        // tekrar çıkış yaptı
                        signInManager.SignOutAsync();

                        // tekrar giriş yaptı. bunu kullanıcı hissetmicek ama cookiesi oluşmul olucak.

                        signInManager.PasswordSignInAsync(user, passwordChangeViewModel.PasswordNew, true, false);

                        // eğer SignOutAsync,PasswordSignInAsync  yapmasaydım IdentityApi 30 dakika içinde sistemden atıcak ve login sayfasına yönlendiricek.

                        ViewBag.success = "true";


                    }
                    else
                    {
                        foreach (var item in result.Errors)
                        {
                            ModelState.AddModelError("", item.Description);
                        }
                    }

                }
                else
                {
                    ModelState.AddModelError("", "Eski şifreniz yanlış");
                }

            }


            //  ModelState.AddModelError("", "Eski şifreniz yanlış"); ile hataları ekledik
            // varsa bunları gösterebilmek için içine passwordChangeViewModel yazıyoruz.
            return View(passwordChangeViewModel);
        }
    }
}
