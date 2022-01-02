using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using IdentitySystemCore.Enums;
using IdentitySystemCore.Models;
using IdentitySystemCore.ViewModels;
using Mapster;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.Extensions.Options;

namespace IdentitySystemCore.Controllers
{
    

    [Authorize]// membercontrollere sadece üyeler erişecek.
    public class MemberController : BaseController
    {
        private readonly TwoFactorService.TwoFactorService _twoFactorService;
        public MemberController(UserManager<AppUser> userManager, SignInManager<AppUser> signInManager, TwoFactorService.TwoFactorService twoFactorService) : base(userManager, signInManager)
        {
            _twoFactorService = twoFactorService;
        }


        public IActionResult Index()
        {
            // kullanıcı bir siteye geldiği zaman, üye de olsa olmasada user classı oluşturur
            // bir tane kimliği oluşur, eğer kullanıcı giriş yapmamışsa isauthenticate false olur.
            // boş bir kimlik oluşur. login olursa biz name,usernama gibi alanları yakalayabiliriz.
            //User.Identity.


            AppUser user = CurrentUser;
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
            AppUser user = CurrentUser;



            UserViewModel userViewModel = user.Adapt<UserViewModel>();

            ViewBag.Gender = new SelectList(Enum.GetNames(typeof(Gender)));

            return View(userViewModel);// kullanıcı bilgileri güncellicek bu yüzden UserViewModel'i dolu olarak gönderiyorum.
        }


        [HttpPost]
        public async Task<IActionResult> UserEdit(UserViewModel userViewModel, IFormFile userPicture)
        {
            ModelState.Remove("Password");
            ViewBag.Gender = new SelectList(Enum.GetNames(typeof(Gender)));
            if (ModelState.IsValid)
            {


                AppUser user = CurrentUser;

                string phone = userManager.GetPhoneNumberAsync(user).Result;

                if (phone != userViewModel.PhoneNumber)
                {

                    if (userManager.Users.Any(u => u.PhoneNumber == userViewModel.PhoneNumber))
                    {
                        ModelState.AddModelError("", "Bu Telefon Numarası Başka Üye Tarafından Kullanılmaktadır.");
                        return View(userViewModel);
                    }

                }

                if (userPicture != null && userPicture.Length > 0)
                {
                    //GetExtension, userPicture'in uzantısını alır jpg,png gibi
                    //Guid.NewGuid().ToString() yaparak isim oluşturuyoruz rastgele
                    var fileName = Guid.NewGuid().ToString() + Path.GetExtension(userPicture.FileName);

                    // wwwroot'un yolunu alıyorum.
                    var path = Path.Combine(Directory.GetCurrentDirectory(), "wwwroot/UserPicture", fileName);

                    using (var stream = new FileStream(path, FileMode.Create))
                    {
                        await userPicture.CopyToAsync(stream);

                        // statik dosyaların hepsi wwwroot içinde olması gerekiyor.
                        user.Picture = "/UserPicture/" + fileName;
                    }

                }



                // güncelliyoruz.
                user.UserName = userViewModel.UserName;
                user.Email = userViewModel.Email;
                user.PhoneNumber = userViewModel.PhoneNumber;
                user.City = userViewModel.City;
                user.BirthDay = userViewModel.BirthDay;
                user.Gender = (int)userViewModel.Gender;

                // startuptaki hatalar geçerli. burdaki hataları Update yaparken bir hata ile karşılaşırsa
                // bunu IdentityResult  resulta atacak
                // UpdateAsync hem custom validationları hem de startup tarafındaki validationları içeriyior//
                IdentityResult result = await userManager.UpdateAsync(user);

                if (result.Succeeded)
                {
                    await userManager.UpdateSecurityStampAsync(user);

                    // tekrar çıkış yaptı
                    await signInManager.SignOutAsync();

                    // true dememizin amacı cookie 60 gün geçerli olcak demek (60) günü belirtmiştik 

                    await signInManager.SignInAsync(user, true);

                    ViewBag.Success = "true";
                }
                else
                {
                    AddModelError(result);
                }


            }

            return View(userViewModel);

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
                AppUser user = CurrentUser;


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
                        AddModelError(result);
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


        public void LogOut()
        {
            signInManager.SignOutAsync();

        }

        public IActionResult AccessDenied(string returnUrl)
        {

            if (returnUrl.Contains("ViolencePage"))
            {
                ViewBag.message = "Erişmeye çalıştığınız sayfa şiddet videoları içerdiğinden dolayı 15 yaşından büyük olmanız gerekmektedir.";
            }
            else if (returnUrl.Contains("AnkaraPage"))
            {
                ViewBag.message = "Bu sayfaya sadece şehir alanı ankara olan kullanıcılar erişebilir.";
            }
            else if (returnUrl.Contains("Exchange"))
            {
                ViewBag.message = "30 günlük kullanım süreniz dolmuştur.";
            }
            else
            {
                ViewBag.message = "Bu sayfaya erişim izniniz yoktur. erişim izni için yöneticiyle görüşünüz.";
            }

            return View();
        }



        [Authorize(Roles = "Admin,Manager")]
        public IActionResult Manager()
        {
            // burdaki actiona artık sadece manager rolüne sahip olanlar girecek.
            return View();
        }


        [Authorize(Roles = "Editor,Admin")]
        public IActionResult Editor()
        {
            // burdaki actiona artık sadece editor rolüne sahip olanlar girecek.
            return View();
        }

        [Authorize(Policy = "AnkaraPolicy")]
        public IActionResult AnkaraPage()
        {
            return View();
        }

        [Authorize(Policy = "ViolencePolicy")]
        public IActionResult ViolencePage()
        {
            return View();
        }

        // ilk kullanıcı giriş yaptığında kullaınıcı ile ilgili claimi veritabanında tutmam lazım
        // Exchange sayfasına gitmeden önceki sayfamız.
        public async Task<IActionResult> ExchangeRedirect()
        {
            // böyle bir claim var mı yok mu bunu buluyoruz
            bool result = User.HasClaim(x => x.Type == "ExpireDateExchange");

            // claim yoksa eklemem lazım, demekki kullanıcı ilk defa borsa grafikleri linkine tıklıyordur demektir.
            // Kullanıcı tıklamıştır 10 gün sonra gelmiştir. varolan şeyi claims olarak eklemeyelim.
            if (!result)
            {
                // 30 gün ileriye eklenmiş bir tarih ekliyorum.
                // ilk kullanıcı bu sayfaya tıkladığı zaman veritabanında ExpireDateExchange olan valuesi ise şuanki tarihten 30 gün sonraki ileriki bir tarih olan bir tarih yazacam.
                // 30 gün içerisinde erişebilir. 30 günü geçtikten sonra erişemez.
                Claim ExpireDateExchange = new Claim("ExpireDateExchange", DateTime.Now.AddDays(30).Date.ToShortDateString(), ClaimValueTypes.String, "Internal");
                await userManager.AddClaimAsync(CurrentUser, ExpireDateExchange);
                await signInManager.SignOutAsync();
                await signInManager.SignInAsync(CurrentUser, true);
            }

            return RedirectToAction("Exchange");
        }

        // Kullanıcı yetkiliyse girebileceği sayfa

        [Authorize(Policy = "ExchangePolicy")]
        public IActionResult Exchange()
        {
            return View();
        }

        public async Task<IActionResult> TwoFactorWithAuthenticator()
        {
            string unformattedkey = await userManager.GetAuthenticatorKeyAsync(CurrentUser);
            if (string.IsNullOrEmpty(unformattedkey))
            {
                await userManager.ResetAuthenticatorKeyAsync(CurrentUser);

                unformattedkey = await userManager.GetAuthenticatorKeyAsync(CurrentUser);
            }

            AuthenticatorViewModel authenticatorViewModel = new AuthenticatorViewModel();

            authenticatorViewModel.SharedKey = unformattedkey;
            authenticatorViewModel.AuthenticatorUri =
                _twoFactorService.GenerateQrCodeUri(CurrentUser.Email, unformattedkey);

            return View(authenticatorViewModel);
        }

        [HttpPost]
        public async Task<IActionResult> TwoFactorWithAuthenticator(AuthenticatorViewModel authenticatorViewModel)
        {
            var verificationCode = authenticatorViewModel.VerificationCode.Replace(" ", string.Empty)
                .Replace("-", string.Empty);

            var is2FATokenValid = await userManager.VerifyTwoFactorTokenAsync(CurrentUser,
                userManager.Options.Tokens.AuthenticatorTokenProvider, verificationCode);
            if (is2FATokenValid)
            {
                CurrentUser.TwoFactorEnabled = true;
                CurrentUser.TwoFactor = (sbyte) TwoFactor.MicrosoftGoogle;

                var recoveryCodes = await userManager.GenerateNewTwoFactorRecoveryCodesAsync(CurrentUser, 5);
                TempData["recoveryCodes"] = recoveryCodes;
                TempData["message"] = "İki Adımlı Kimlik Doğrulama Tipiniz Microsoft/Google Olarak Belirlenmiştir.";

                return RedirectToAction("TwoFactorAuth");
            }
            else
            {
                ModelState.AddModelError("","Girdiğiniz Doğrulama Kodu Yanlıştır");
                return View(authenticatorViewModel);
            }

 
        }

        public IActionResult TwoFactorAuth()
        {
            return View(new AuthenticatorViewModel(){TwoFactorType = (TwoFactor)CurrentUser.TwoFactor});
        }

        [HttpPost]
        public async Task<IActionResult> TwoFactorAuth(AuthenticatorViewModel authenticatorViewModel)
        {
            switch (authenticatorViewModel.TwoFactorType)   
            {
                case TwoFactor.None:
                    CurrentUser.TwoFactorEnabled = false;
                    CurrentUser.TwoFactor = (sbyte)TwoFactor.None;
                    TempData["message"] = "İki Adımlı Kimlik Doğrulama Tipiniz Hiçbiri Olarak Belirlenmiştir.";
                    break;
                case TwoFactor.MicrosoftGoogle:
                    return RedirectToAction("TwoFactorWithAuthenticator");
                   
            }

            await userManager.UpdateAsync(CurrentUser);
            return View(authenticatorViewModel);
        }

    }
}
