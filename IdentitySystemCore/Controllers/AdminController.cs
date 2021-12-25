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


        public IActionResult Users()
        {
            return View(userManager.Users.ToList());
        }

    }
}
