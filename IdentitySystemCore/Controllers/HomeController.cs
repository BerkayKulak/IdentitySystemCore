using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using IdentitySystemCore.Models;
using IdentitySystemCore.ViewModels;
using Microsoft.AspNetCore.Identity;

namespace IdentitySystemCore.Controllers
{
    public class HomeController : Controller
    {
        public HomeController(UserManager<AppUser> userManager, SignInManager<AppUser> signInManager)
        {
            this.userManager = userManager;
            this.signInManager = signInManager;
        }

        public UserManager<AppUser> userManager { get; }
        public SignInManager<AppUser> signInManager { get; }

        public IActionResult Index()
        {
            return View();
        }

        public IActionResult LogIn(string ReturnUrl)
        {
            TempData["ReturnUrl"] = ReturnUrl; // actionlar içinde veriler tutabiliriz. sayfalar arası
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> LogIn(LoginViewModel userlogin)
        {

            if (ModelState.IsValid)
            {
                // kullanıcının emailine bakıyorum.
                AppUser user = await userManager.FindByEmailAsync(userlogin.Email);

                if (user != null)
                {
                    // sistemde eski bir cookie varsa silinsin. kullanıcı tekrar login oluyor tekrar oluşur.
                    // isPersistent = true yaparsak cookie ömrü belirleriz. onuda startupda 60 gün olarak belirledik.
                    // LockoutonFailure kullanıcı şifreyi durmadan yanlış girerse kitlesin mi demek
                    await signInManager.SignOutAsync();
                    Microsoft.AspNetCore.Identity.SignInResult result = await signInManager.PasswordSignInAsync(user, userlogin.Password, userlogin.RememberMe, false);
                    if (result.Succeeded)
                    {
                        if (result.Succeeded)
                        {
                            if (TempData["ReturnUrl"] != null)
                            {
                                return Redirect(TempData["ReturnUrl"].ToString());
                            }
                            return RedirectToAction("Index", "Member");
                        }


                        return RedirectToAction("Index", "Member");
                    }

                }
                else
                {
                    ModelState.AddModelError("", "Geçersiz Email adresi veya şifresi");
                }
            }
            return View(userlogin);
        }


        public IActionResult SignUp()
        {
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> SignUp(UserViewModel userViewModel)
        {
            // gelen verilerin doğru olup olmadığını kontrol etmek
            // backend tarafında hem client tarafında kontrol yapıyprum ajaxda 
            // bunu otomatik olarak jquerry gerçekleştirecek bizim mvc mimarisi gereği

            // olurda kullanıcı javascript özelliğini kapatırsa client tarafında doğrulama yapamam
            // ben bu doğrulamayı backend tarafında yapmam lazım


            if (ModelState.IsValid)
            {
                AppUser user = new AppUser();
                user.UserName = userViewModel.UserName;
                user.Email = userViewModel.Email;
                user.PhoneNumber = userViewModel.PhoneNumber;

                // şuanda şifreyi eklemicem çünkü plan text olarak gelir. bunu hashliceğimizden getirmiyoruz.
                // await derkei bak kardeşim bu metod yani bu satır bitmeden alt satıra geçme, sonucu ata ve alta geç


                // IdentityResult bize = üye oluştururken bir hata olursa biz bunu result üzerinden yakalayabileceğiz.


                IdentityResult result = await userManager.CreateAsync(user, userViewModel.Password);

                // 1.senaryo bazı web siteleri ilk kayıt işlemi gerçekleştiğinde aynı zamanda login işlemide gerçekleştiriyor
                // 2.senaryo bazı web siteleri kullanıı üye olduktan sonra kullanıcıyı login ekranına yönlendiriyor.
                if (result.Succeeded)
                {
                    // eğer kullanıcı gerçekten başarılı bir şekilde kayıt olmuşsa 
                    // giriş ekranına yönlendiririm. biz kayıt olduktan sonra giriş ekranına yönlendireceğiz
                    // 2.senaryo

                    // LogIn ekranına gidecek
                    return RedirectToAction("LogIn");
                }
                // başarılı olmadıysa
                else
                {
                    foreach (IdentityError item in result.Errors)
                    {
                        ModelState.AddModelError("", item.Description);
                    }
                    // key değeri göndermedim hataları asp-validation-summary kısmında göstereceğim demektir
                    // key gönderirsem özel spesifik bir alanı belirtiyorum demek.

                }
            }

            // bu userviewmodeli şu hataları ekle kullanıcıya tekrar gönder.
            // kullanıcı değerleri girdikten sonra bir hata varsa 0 dan tekrar girmesin
            // girdiği değerlerle birlikte tekrar göngderiyorum. hata varsa hatalarıda gönderiyorum.
            return View(userViewModel);

        }


    }
}
