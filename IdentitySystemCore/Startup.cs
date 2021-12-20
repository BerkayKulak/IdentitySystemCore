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
            // istemiþ olduðu sýnýfýn bir nesne örneðini oluþturur.
            services.AddDbContext<AppIdentityDbContext>(opts =>
            {// appsettings.jsondan geliyor = "ConnectionStrings:DefaultConnectionString"
                opts.UseSqlServer(Configuration["ConnectionStrings:DefaultConnectionString"]);

            });
            //IdentityUseri' App user olarak miras aldýk.
            // IdentityRole ile miras alma iþlemi gerçekleþtirmediðimizden kullanýyoruz.
            //IdentityUseri' App user olarak miras aldýk.
            // IdentityRole ile miras alma iþlemi gerçekleþtirmediðimizden kullanýyoruz.

            // ok iþareti çýkarttýðým zaman
            // bana gidip o ctordan istemiþ olduðu classtan bir tane class oluþturuyor.
            services.AddIdentity<AppUser, AppRole>(opts => {
                opts.User.RequireUniqueEmail = true;
                opts.User.AllowedUserNameCharacters
                    = "abcçdefghýijklmnoöpqrsþtuüvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._";
                opts.Password.RequiredLength = 4; // default olarak en az 4 karakter isticez.
                opts.Password.RequireNonAlphanumeric = false; // yýldýz ya da nokta gibi karakter istemiyor
                opts.Password.RequireLowercase = false; // küçük harf istemiyorum
                opts.Password.RequireUppercase = false; // büyük harf istemiyorum.
                opts.Password.RequireDigit = false;// sayýsal karakter de istemiyorum 

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
