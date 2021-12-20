using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.HttpsPolicy;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using IdentitySystemCore.CustomValidator;
using IdentitySystemCore.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace IdentitySystemCore
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            // istemi� oldu�u s�n�f�n bir nesne �rne�ini olu�turur.
            services.AddDbContext<AppIdentityDbContext>(opts =>
            {// appsettings.jsondan geliyor = "ConnectionStrings:DefaultConnectionString"
                opts.UseSqlServer(Configuration["ConnectionStrings:DefaultConnectionString"]);

            });
            //IdentityUseri' App user olarak miras ald�k.
            // IdentityRole ile miras alma i�lemi ger�ekle�tirmedi�imizden kullan�yoruz.
            //IdentityUseri' App user olarak miras ald�k.
            // IdentityRole ile miras alma i�lemi ger�ekle�tirmedi�imizden kullan�yoruz.

            // ok i�areti ��kartt���m zaman
            // bana gidip o ctordan istemi� oldu�u classtan bir tane class olu�turuyor.
            services.AddIdentity<AppUser, AppRole>(opts => {
                opts.User.RequireUniqueEmail = true;
                opts.User.AllowedUserNameCharacters
                    = "abc�defgh�ijklmno�pqrs�tu�vwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._";
                opts.Password.RequiredLength = 4; // default olarak en az 4 karakter isticez.
                opts.Password.RequireNonAlphanumeric = false; // y�ld�z ya da nokta gibi karakter istemiyor
                opts.Password.RequireLowercase = false; // k���k harf istemiyorum
                opts.Password.RequireUppercase = false; // b�y�k harf istemiyorum.
                opts.Password.RequireDigit = false;// say�sal karakter de istemiyorum 

            }).AddPasswordValidator<CustomPasswordValidator>().
                AddUserValidator<CustomUserValidator>().AddErrorDescriber<CustomIdentityErrorDescriber>().
                AddEntityFrameworkStores<AppIdentityDbContext>();
            

            services.AddMvc();
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {

            app.UseDeveloperExceptionPage();
            app.UseStatusCodePages();
            app.UseStaticFiles();


            //if (env.IsDevelopment())
            //{
            //    app.UseDeveloperExceptionPage();
            //}
            //else
            //{
            //    app.UseExceptionHandler("/Error");
            //    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
            //    app.UseHsts();
            //}

            //app.UseHttpsRedirection();
            //app.UseStaticFiles();

            app.UseRouting();

            app.UseAuthorization();
            app.UseAuthentication();

            app.UseEndpoints(endpoints =>
            {

                endpoints.MapControllerRoute(
                    name: "default",
                    pattern: "{controller=Home}/{action=Index}/{id?}");
            });
        }
    }
}
