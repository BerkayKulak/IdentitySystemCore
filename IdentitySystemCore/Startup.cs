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
using Microsoft.AspNetCore.Http;
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


            CookieBuilder cookieBuilder = new CookieBuilder();
            cookieBuilder.Name = "MyBlog";
            // k�t� niyetli kullan�c�lar client side tarafta benim cookime eri�emez.
            // http iste�i �zerinden cookie bilgisini almak istiyorum.
            cookieBuilder.HttpOnly = false;
            // s�re belirtelim. ne kadar s�re kullan�c�n�n bilgisayar�nda kals�n
            // cookie 60 g�n boyunca kalacak, login olduktan sonra 60 g�n gezinebilecek. sonra tekrar login olams� laz�m

            // sadece benim sitem �zerinden gelen cookie ayarlar�n� al
            cookieBuilder.SameSite = SameSiteMode.Lax;
            // always dersek browser sizin cookiesini , sadece bir https �zerinden bir istek gelmi�se g�nderiyor.
            // SameAsRequest dersek, e�er bu cookie bilgisi http �zerinden gelmi�se http den g�nderiyor
            // https derseniz htpps �zerinden g�nderir
            // None dersek isterse https olsun ister http olsun hepsini http �zeirnden getiriyor.
            cookieBuilder.SecurePolicy = CookieSecurePolicy.SameAsRequest;

            services.ConfigureApplicationCookie(opts =>
            {
                
                // kullan�c� �ye olmadan, �yelerin eri�ebildi�i bir sayfaya t�klarsa kullan�c�y� login sayfas�na y�nlendiririz.
                opts.LoginPath = new PathString("/Home/Login");

                opts.Cookie = cookieBuilder;

                // kullan�c�y�a 60 g�n vermi�tik ya hani, e�er siz SlidingExpiration s�resini true yaparsan�z.
                // 60'�n yar�s�n� ge�tikten sonra e�er siteye istek yaparsa tekrar bi 60 g�n daha eklicek.
                opts.SlidingExpiration = true;
                opts.ExpireTimeSpan = System.TimeSpan.FromDays(60);
            });


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
