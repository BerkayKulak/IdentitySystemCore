using Microsoft.AspNetCore.Mvc;
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
    [Authorize(Roles = "Admin")]
    public class AdminController : BaseController
    {


        public AdminController(UserManager<AppUser> userManager,RoleManager<AppRole> roleManager):base(userManager,null,roleManager)
        {
            
        }

        public IActionResult Index()
        {
            // veritabanındaki usersları çektik ve listeye attık
            return View();
        }

        public IActionResult Users()
        {
            return View(userManager.Users.ToList());
        }

        public IActionResult RoleCreate()
        {
            return View();
        }

        [HttpPost]
        public IActionResult RoleCreate(RoleViewModel roleViewModel)
        {
            AppRole role = new AppRole();
            role.Name = roleViewModel.Name;
            IdentityResult result = roleManager.CreateAsync(role).Result;

            if (result.Succeeded)
            {
                return RedirectToAction("Roles");
            }
            else
            {
                AddModelError(result);
            }

            return View(roleViewModel);
        }

        public IActionResult Roles()
        {
            return View(roleManager.Roles.ToList());
        }

        public IActionResult RoleDelete(string id)
        {
            AppRole role = roleManager.FindByIdAsync(id).Result;
            if (role != null)
            {
                IdentityResult result = roleManager.DeleteAsync(role).Result;


            }


            return RedirectToAction("Roles");
        }

        public IActionResult RoleUpdate(string id)
        {
            AppRole role = roleManager.FindByIdAsync(id).Result;

            if (role != null)
            {
                // role içerisinden gelen(AppRole) Id ve name kısmı
                // benim RoleViewModeldeki Id ve name kısmı ile eşleşir.
                return View(role.Adapt<RoleViewModel>());

            }
            return RedirectToAction("Roles");
        }

        [HttpPost]
        public IActionResult RoleUpdate(RoleViewModel roleViewModel)
        {
            // böyle bir ıd var mı onu güncellicez.
            AppRole role = roleManager.FindByIdAsync(roleViewModel.Id).Result;
            if (role != null)
            {
                role.Name = roleViewModel.Name;
                IdentityResult result = roleManager.UpdateAsync(role).Result;

                if (result.Succeeded)
                {
                    return RedirectToAction("Roles");
                }
                else
                {
                    AddModelError(result);
                }

            }
            else
            {
                ModelState.AddModelError("", "Güncelleme işlemi başarısız oldu.");
            }
            return View(roleViewModel);
        }

        public IActionResult RoleAssign(string id)
        {
            // idyi tempdata da saklıyoruz. id değerini alıyoruz.
            // sonra bu id yi diğer fonksiyonda yakalıcaz
            TempData["userId"] = id;

            AppUser user = userManager.FindByIdAsync(id).Result;

            ViewBag.userName = user.UserName;

            IQueryable<AppRole> roles = roleManager.Roles;

            // kullanıcının sahip olduğu rolleri arka planda list olarak dönecek.
            // cast ettik as diyerek.
            List<string> userroles = userManager.GetRolesAsync(user).Result as List<string>;

            List<RoleAssignViewModel> roleAssignViewModels = new List<RoleAssignViewModel>();


            // veritabanındaki rol benim veritabanımda var mı ?

            foreach (var role in roles)
            {
                RoleAssignViewModel r = new RoleAssignViewModel();
                r.RoleId = role.Id;
                r.RoleName = role.Name;
                if (userroles.Contains(role.Name))
                {

                    // checkbox işaretli mi olcak
                    // eğer kullanıcı burdaki role sahipse checkbox işaretli olsun.
                    r.Exist = true;
                }
                else
                {

                    r.Exist = false;
                }
                roleAssignViewModels.Add(r);// listemi dolduruyorum.

            }


            return View(roleAssignViewModels);

        }

        [HttpPost]
        public async Task<IActionResult> RoleAssign(List<RoleAssignViewModel> roleAssignViewModel)
        {
            AppUser user = userManager.FindByIdAsync(TempData["userId"].ToString()).Result;
            foreach (var item in roleAssignViewModel)
            {
                // checkbox atanmış ise tıklanmış olduğu rolü kullanıcıya ata
                if (item.Exist)

                {
                    await userManager.AddToRoleAsync(user, item.RoleName);

                }
                else
                {
                    // checkbox işaretli değilse rolü kaldır.
                    await userManager.RemoveFromRoleAsync(user, item.RoleName);
                }
            }

            return RedirectToAction("Users");
        }

        public IActionResult Claims()
        {
            return View(User.Claims.ToList());
        }

        public async Task<IActionResult> ResetUserPassword(string id)
        {
            AppUser user = await userManager.FindByIdAsync(id);
            PasswordResetByAdminViewModel passwordResetByAdminViewModel = new PasswordResetByAdminViewModel();
            passwordResetByAdminViewModel.UserId = user.Id;
            return View(passwordResetByAdminViewModel);
        }

        [HttpPost]
        public async Task<IActionResult> ResetUserPassword(PasswordResetByAdminViewModel passwordResetByAdminViewModel)
        {
            AppUser user = await userManager.FindByIdAsync(passwordResetByAdminViewModel.UserId);

            string token = await userManager.GeneratePasswordResetTokenAsync(user);

            await  userManager.ResetPasswordAsync(user, token, passwordResetByAdminViewModel.NewPassword);

            await userManager.UpdateSecurityStampAsync(user);

            // security stamp değerini update etmezsem kullanıcı eski şifresiyle sitemizde dolaşmaya devam eder.
            // ne zaman çıkış yaparsa, o zaman yeni şifre ile girmek zorunda
            // eğer update edersem kullanıcı otomatik olarak sitemize girdiği zaman login ekranına yönlendirir.

            return RedirectToAction("Users");

        }
    }
}
