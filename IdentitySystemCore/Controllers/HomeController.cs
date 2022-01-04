using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using IdentitySystemCore.Enums;
using IdentitySystemCore.Models;
using IdentitySystemCore.TwoFactorService;
using IdentitySystemCore.ViewModels;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;

namespace IdentitySystemCore.Controllers
{
    public class HomeController : BaseController
    {
        private readonly TwoFactorService.TwoFactorService _twoFactorService;
        private readonly EmailSender _emailSender;
        public HomeController(UserManager<AppUser> userManager, SignInManager<AppUser> signInManager, TwoFactorService.TwoFactorService twoFactorService, EmailSender emailSender) : base(userManager, signInManager)
        {
            _twoFactorService = twoFactorService;
            _emailSender = emailSender;
        }

        public IActionResult Index()
        {
            // kullanıcı login olmuşsa önceden bu sayfayı göster direk olarak
            if (User.Identity.IsAuthenticated)
            {
                return RedirectToAction("Index", "Member");
            }
            return View();
        }

        public IActionResult LogIn(string ReturnUrl="/")
        {
            TempData["ReturnUrl"] = ReturnUrl; // actionlar içinde veriler tutabiliriz. sayfalar arası
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> LogIn(LoginViewModel userlogin)
        {

            if (ModelState.IsValid)
            {
                AppUser user = await userManager.FindByEmailAsync(userlogin.Email);

                if (user != null)
                {
                    // öncelikle kullanıcı var ve kilitli olup olmadığını anlamam lazım
                    if (await userManager.IsLockedOutAsync(user))
                    {
                        ModelState.AddModelError("", "Hesabınız bir süreliğine kilitlenmiştir. Lütfen daha sonra tekrar deneyiniz.");
                        return View(userlogin);
                    }

                    if (userManager.IsEmailConfirmedAsync(user).Result == false)
                    {
                        ModelState.AddModelError("", "Email Adresiniz Onaylanmamıştır. Lütfen epostanızı kontrol ediniz.");
                        return View(userlogin);
                    }

                    // await signInManager.SignOutAsync();

                    //userlogin.RememberMe = cookienin gerçekten geçerli olup olmadığını kontrol edicez. checkboxtan kontrol edicez. işaretlersem true olur.
                    // benim startuptaki 60 gün geçerli olacak
                    // Microsoft.AspNetCore.Identity.SignInResult result = await signInManager.PasswordSignInAsync(user, userlogin.Password, userlogin.RememberMe, false);

                    bool userCheck = await userManager.CheckPasswordAsync(user, userlogin.Password);

                    if (userCheck)
                    {
                        // başarılı giriş yaptığımız için AccessFailedCount değerini 0 lıcak
                        await userManager.ResetAccessFailedCountAsync(user);

                        await signInManager.SignOutAsync();

                        var result = await signInManager.PasswordSignInAsync(user, userlogin.Password,
                            userlogin.RememberMe, false);

                        if (result.RequiresTwoFactor)
                        {
                            if (user.TwoFactor == (int) TwoFactor.Email || user.TwoFactor == (int) TwoFactor.Phone)
                            {
                                HttpContext.Session.Remove("currentTime");
                            }
                            return RedirectToAction("TwoFactorLogIn");
                            
                        }
                        else
                        {

                            return Redirect(TempData["ReturnUrl"].ToString());

                        }
                    }

                    else
                    {
                        // başarısız girişte 1 artıcak
                        await userManager.AccessFailedAsync(user);
                        // kaç başarısız giriş yaptı alır.
                        int fail = await userManager.GetAccessFailedCountAsync(user);

                        ModelState.AddModelError("", $"{fail} kez başarısız giriş.");

                        if (fail == 3)
                        {
                            // kullanıcıyı 20 dakka kilitliyoruz
                            await userManager.SetLockoutEndDateAsync(user, new System.DateTimeOffset(DateTime.Now.AddMinutes(20)));


                            ModelState.AddModelError("", "Hesabınız 3 başarısız girişten dolayı 20 dakika süreyle kilitlenmiştir.");
                        }

                        else
                        {
                            ModelState.AddModelError("", "Email adresi veya şifre Yanlış");

                        }

                    }
                }
                else
                {
                    ModelState.AddModelError("", "Bu email adresine kayıtlı kullanıcı bulunamamıştır.");
                }
            }
            return View(userlogin);
        }

        [HttpGet]
        public async Task<IActionResult> TwoFactorLogIn(string ReturnUrl = "/")
        {
            var user = await signInManager.GetTwoFactorAuthenticationUserAsync();
            TempData["ReturnUrl"] = ReturnUrl;

            switch ((TwoFactor)user.TwoFactor)
            {
                case TwoFactor.MicrosoftGoogle:
                    break;
                case TwoFactor.Email:
                    if (_twoFactorService.TimeLeft(HttpContext) == 0)
                    {
                        return RedirectToAction("LogIn");
                    }

                    ViewBag.timeleft = _twoFactorService.TimeLeft(HttpContext);

                    HttpContext.Session.SetString("codeverification",_emailSender.Send(user.Email));

                    break;


            }

            return View(new TwoFactorLoginViewModel(){TwoFactorType = (TwoFactor)user.TwoFactor,isRecoverCode = false,isRememberMe = false,VerificationCode = string.Empty});

        }

        [HttpPost]
        public async Task<IActionResult> TwoFactorLogIn(TwoFactorLoginViewModel twoFactorLoginViewModel)
        {
            var user = await signInManager.GetTwoFactorAuthenticationUserAsync();
            ModelState.Clear();
            bool isSuccessAuth = false;
            if ((TwoFactor) user.TwoFactor == TwoFactor.MicrosoftGoogle)
            {
                Microsoft.AspNetCore.Identity.SignInResult result;

                if (twoFactorLoginViewModel.isRecoverCode)
                {
                    result = await signInManager.TwoFactorRecoveryCodeSignInAsync(twoFactorLoginViewModel
                        .VerificationCode);
                }
                else
                {
                    result = await signInManager.TwoFactorAuthenticatorSignInAsync(
                        twoFactorLoginViewModel.VerificationCode, twoFactorLoginViewModel.isRememberMe, false);
                }

                if (result.Succeeded)
                {
                    isSuccessAuth = true;
                }
                else
                {
                    ModelState.AddModelError("","Doğrulama kodu yanlış");
                }
            }

            if (isSuccessAuth)
            {
                return Redirect(TempData["ReturnUrl"].ToString());
            }

            twoFactorLoginViewModel.TwoFactorType = (TwoFactor) user.TwoFactor;

            return View(twoFactorLoginViewModel);
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

                if (userManager.Users.Any(u => u.PhoneNumber == userViewModel.PhoneNumber))
                {
                    ModelState.AddModelError("", "Bu Telefon Numarası kayıtlıdır.");
                    return View(userViewModel);
                }


                AppUser user = new AppUser();
                user.UserName = userViewModel.UserName;
                user.Email = userViewModel.Email;
                user.PhoneNumber = userViewModel.PhoneNumber;
                user.TwoFactor = 0;

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

                    // email doğrualama tokeni oluşturuyor. benim vermiş olduğum userdaki bilgiler ile token oluşturacak
                    string confirmationToken = await userManager.GenerateEmailConfirmationTokenAsync(user);

                    // kullanıcı linke tıkladığı zaman gideceği sayfa ConfirmEmail olacak
                    string link = Url.Action("ConfirmEmail", "Home", new
                    {
                        userId = user.Id,
                        token = confirmationToken


                    }, protocol: HttpContext.Request.Scheme);

                    Helper.EmailConfirmation.SendEmail(link, user.Email);


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

        public IActionResult ResetPassword()
        {
            return View();
        }

        [HttpPost]
        public IActionResult ResetPassword(PasswordResetViewModel passwordResetViewModel)
        {
            // benim veritabanımda kayıtlı kullanıcı var mı onu tespit edelim önce
            AppUser user = userManager.FindByEmailAsync(passwordResetViewModel.Email).Result;

            if (user != null)
            {
                // userManager.GeneratePasswordResetTokenAsync(user) bunu yaptığımız zaman
                // user bilgilerinden oluşan bir tane token oluşuyor.
                // Token içerisinde SecurityStamp(kullanıcının önemli parametresi(username,password) değiştiği zaman bunu değiştiriyoruz)
                // token = id,email,securitystamp gibi değerler var.

                string passwordResetToken = userManager.GeneratePasswordResetTokenAsync(user).Result;

                // kullanıcı linke tıkladığı zaman burdaki view ' a gelicek
                string passwordResetLink = Url.Action("ResetPasswordConfirm", "Home", new
                {

                    userId = user.Id,
                    token = passwordResetToken

                }, HttpContext.Request.Scheme);


                // www.bıdıbıdı.com/Home/ResetPasswordConfirm?userId = asdfd&token = adgsg

                Helper.PasswordReset.PasswordResetSendEmail(passwordResetLink, user.Email);

                ViewBag.status = "successfull";

            }
            else
            {
                ModelState.AddModelError("", "Sistemde kayıtlı email adresi bulunamamıştır.");

            }


            return View(passwordResetViewModel);
        }

        public IActionResult ResetPasswordConfirm(string userId, string token)
        {
            TempData["userId"] = userId;
            TempData["token"] = token;

            return View();
        }

        [HttpPost]

        // Bind = PasswordResetViewModel classına hangi değerlerin geleceğini belirtiyoruz. Emaili belirtmedik mesela
        public async Task<IActionResult> ResetPasswordConfirm([Bind("PasswordNew")] PasswordResetViewModel passwordResetViewModel)
        {
            //TempData = sayfalar arası veri taşımak için kullanıyoruz.
            string token = TempData["token"].ToString();
            string userId = TempData["userId"].ToString();

            AppUser user = await userManager.FindByIdAsync(userId);

            if (user != null)
            {
                // şifrem sıfırlanacak
                IdentityResult result = await userManager.ResetPasswordAsync(user, token, passwordResetViewModel.PasswordNew);

                // başarılıysa 0 lanmış demektir.
                // SecurityStampi Update edecez
                // SecurityStamp = kullanıcının bilgileriye alakalı bir o anki anlık durumu tutan bir stampti
                // önemli bir bilgiyi değiştirdiğimiz zaman veritabanında SecurityStampi de değiştiriyoruz
                // mesela telefon numarası değişiyorsa gerek yok, özellikle username,password gibi alanlarda değiştir.

                if (result.Succeeded)
                {
                    // bunu yapmazsak eski şifreyle dolaşmaya devam eder.
                    await userManager.UpdateSecurityStampAsync(user);

                    ViewBag.status = "success";
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
                ModelState.AddModelError("", "Hata meydana gelmiştir. Lütfen daha sonra tekrar deneyiniz.");
            }

            return View(passwordResetViewModel);
        }

        public async Task<IActionResult> ConfirmEmail(string userId, string token)
        {
            var user = await userManager.FindByIdAsync(userId);

            IdentityResult result = await userManager.ConfirmEmailAsync(user, token);

            if (result.Succeeded)
            {
                ViewBag.status = "Email adressiniz onaylanmıştır. Login ekranından giriş yapabilirsiniz.";
            }
            else
            {
                ViewBag.status = "Bir hata meydana geldi. Lütfen daha sonra tekrar deneyiniz.";
            }


            return View();

        }

        public IActionResult FacebookLogin(string ReturnUrl)
        {
            // döneceği sayfayı belirttik
            string RedirectUrl = Url.Action("ExternalResponse", "Home", new { ReturnUrl });

            var properties = signInManager.ConfigureExternalAuthenticationProperties("Facebook", RedirectUrl);

            return new ChallengeResult("Facebook", properties);

        }


        public IActionResult GoogleLogin(string ReturnUrl)
        {
            // döneceği sayfayı belirttik
            string RedirectUrl = Url.Action("ExternalResponse", "Home", new { ReturnUrl });

            var properties = signInManager.ConfigureExternalAuthenticationProperties("Google", RedirectUrl);

            return new ChallengeResult("Google", properties);

        }

        public IActionResult MicrosoftLogin(string ReturnUrl)
        {
            // döneceği sayfayı belirttik
            string RedirectUrl = Url.Action("ExternalResponse", "Home", new { ReturnUrl });

            var properties = signInManager.ConfigureExternalAuthenticationProperties("Microsoft", RedirectUrl);

            return new ChallengeResult("Microsoft", properties);

        }

        public async Task<IActionResult> ExternalResponse(string ReturnUrl = "/")
        {
            ExternalLoginInfo info = await signInManager.GetExternalLoginInfoAsync();

            if (info == null)
            {
                return RedirectToAction("LogIn");
            }
            else
            {
                // cookileri kaç gün boyunca tutalım true dedik 60 gün tutacak
                Microsoft.AspNetCore.Identity.SignInResult signInResult = await signInManager.ExternalLoginSignInAsync(info.LoginProvider, info.ProviderKey, true);

                if (signInResult.Succeeded)
                {
                    return Redirect(ReturnUrl);
                }

                // kullanıcı ilk kez facebook butonuna basıyorsa
                else
                {
                    AppUser appUser = new AppUser();

                    appUser.Email = info.Principal.FindFirst(ClaimTypes.Email).Value;

                    string ExternalUserId = info.Principal.FindFirst(ClaimTypes.NameIdentifier).Value;

                    if (info.Principal.HasClaim(x => x.Type == ClaimTypes.Name))
                    {
                        string userName = info.Principal.FindFirst(ClaimTypes.Name).Value;

                        userName = userName.Replace(" ", "-").ToLower() + ExternalUserId.Substring(0, 5).ToString();

                        appUser.UserName = userName;
                    }
                    else
                    {
                        appUser.UserName = info.Principal.FindFirst(ClaimTypes.Email).Value;
                    }

                    // veritabanında böyle bir kullanıcı var mı y ok mu kontrol ediyorum
                    AppUser user2 = await userManager.FindByEmailAsync(appUser.Email);

                    if (user2 == null)
                    {
                        IdentityResult createResult = await userManager.CreateAsync(appUser);

                        if (createResult.Succeeded)
                        {
                            IdentityResult loginResult = await userManager.AddLoginAsync(appUser, info);

                            if (loginResult.Succeeded)
                            {
                                //await signInManager.SignInAsync(appUser, true);

                                await signInManager.ExternalLoginSignInAsync(info.LoginProvider, info.ProviderKey, true);



                                return Redirect(ReturnUrl);
                            }
                            else
                            {
                                AddModelError(loginResult);
                            }
                        }
                        else
                        {
                            AddModelError(createResult);
                        }
                    }
                    // kullanıcı var ise tabloya ekliyorum. email adresleri aynı sadece bazı değerler değişir
                    else
                    {
                        IdentityResult loginResult = await userManager.AddLoginAsync(user2, info);

                        await signInManager.ExternalLoginSignInAsync(info.LoginProvider, info.ProviderKey, true);

                        return Redirect(ReturnUrl);


                    }

                }
            }

            List<string> errors = ModelState.Values.SelectMany(x => x.Errors).Select(y => y.ErrorMessage).ToList();



            return View("Error", errors);

        }

        public ActionResult Error()
        {
            return View();
        }

    }
}
