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
using IdentitySystemCore.Requirements;
using IdentitySystemCore.TwoFactorService;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
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
            services.Configure<TwoFactorOptions>(Configuration.GetSection("TwoFactorOptions"));
            services.AddScoped<TwoFactorService.TwoFactorService>();
            services.AddTransient<IAuthorizationHandler, ExpireDateExchangeHandler>();
            // istemiþ olduðu sýnýfýn bir nesne örneðini oluþturur.
            services.AddDbContext<AppIdentityDbContext>(opts =>
            {// appsettings.jsondan geliyor = "ConnectionStrings:DefaultConnectionString"
                opts.UseSqlServer(Configuration["ConnectionStrings:DefaultConnectionString"]);

            });

            //claim bazlý yetkilendirme yapmak için bir tane policy eklememiz lazým.
            // bunuda AddAuthorization servisi içerisinde ekliyorum.
            // policy adým = AnkaraPolicy, sözleþme gibi düþün
            //bunu belirtmiþ olduðum yerde kullanýcýnýn mutlaka city claimine sahip olmasý lazým
            // ayný zamanda deðeride ankara olmasý lazým.

            services.AddAuthorization(opts =>
            {
                opts.AddPolicy("AnkaraPolicy", policy =>
                {
                    policy.RequireClaim("city", "ankara");
                });

                opts.AddPolicy("ViolencePolicy", policy =>
                {
                    policy.RequireClaim("violance");
                });

                opts.AddPolicy("ExchangePolicy", policy =>
                {
                    policy.AddRequirements(new ExpireDateExchangeRequirement());
                });

            });

            services.AddAuthentication().AddFacebook(opts =>
            {
                opts.AppId = Configuration["Authentication:Facebook:AppId"];
                opts.AppSecret = Configuration["Authentication:Facebook:AppSecret"];
            }).AddGoogle(opts =>
            {
                opts.ClientId = Configuration["Authentication:Google:ClientId"];
                opts.ClientSecret = Configuration["Authentication:Google:ClientSecret"];
            }).AddMicrosoftAccount(opts =>
            {
                opts.ClientId = Configuration["Authentication:Microsoft:ClientId"];
                opts.ClientSecret = Configuration["Authentication:Microsoft:ClientSecret"];
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
                    = "abcçdefgðhýijklmnoöpqrsþtuüvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._";
                opts.Password.RequiredLength = 4; // default olarak en az 4 karakter isticez.
                opts.Password.RequireNonAlphanumeric = false; // yýldýz ya da nokta gibi karakter istemiyor
                opts.Password.RequireLowercase = false; // küçük harf istemiyorum
                opts.Password.RequireUppercase = false; // büyük harf istemiyorum.
                opts.Password.RequireDigit = false;// sayýsal karakter de istemiyorum 

            }).AddPasswordValidator<CustomPasswordValidator>().
                AddUserValidator<CustomUserValidator>().AddErrorDescriber<CustomIdentityErrorDescriber>().
                AddEntityFrameworkStores<AppIdentityDbContext>().AddDefaultTokenProviders();


            CookieBuilder cookieBuilder = new CookieBuilder();
            cookieBuilder.Name = "MyBlog";
            // kötü niyetli kullanýcýlar client side tarafta benim cookime eriþemez.
            // http isteði üzerinden cookie bilgisini almak istiyorum.
            cookieBuilder.HttpOnly = false;
            // süre belirtelim. ne kadar süre kullanýcýnýn bilgisayarýnda kalsýn
            // cookie 60 gün boyunca kalacak, login olduktan sonra 60 gün gezinebilecek. sonra tekrar login olamsý lazým

            // sadece benim sitem üzerinden gelen cookie ayarlarýný al
            cookieBuilder.SameSite = SameSiteMode.Lax;
            // always dersek browser sizin cookiesini , sadece bir https üzerinden bir istek gelmiþse gönderiyor.
            // SameAsRequest dersek, eðer bu cookie bilgisi http üzerinden gelmiþse http den gönderiyor
            // https derseniz htpps üzerinden gönderir
            // None dersek isterse https olsun ister http olsun hepsini http üzeirnden getiriyor.
            cookieBuilder.SecurePolicy = CookieSecurePolicy.SameAsRequest;

            services.ConfigureApplicationCookie(opts =>
            {
                
                // kullanýcý üye olmadan, üyelerin eriþebildiði bir sayfaya týklarsa kullanýcýyý login sayfasýna yönlendiririz.
                opts.LoginPath = new PathString("/Home/Login");
                opts.LogoutPath = new PathString("/Member/LogOut");
                opts.Cookie = cookieBuilder;

                // kullanýcýyýa 60 gün vermiþtik ya hani, eðer siz SlidingExpiration süresini true yaparsanýz.
                // 60'ýn yarýsýný geçtikten sonra eðer siteye istek yaparsa tekrar bi 60 gün daha eklicek.
                opts.SlidingExpiration = true;
                opts.ExpireTimeSpan = System.TimeSpan.FromDays(60);

                // eðer kullanýcý üye olduktan sonra, admin linkine týklarsa, editor rolüne sahip ama yönetici rolüne týklarsa 
                // bu sayfaya eriþemediðiyle ilgili bir bilgi verilir. Eriþime yetkisi olmayan üye kullanýcýlarýn gideceði path olacak
                opts.AccessDeniedPath = new PathString("/Member/AccessDenied");

            });

            // bu classýn her request iþleminde bu dönüþüm iþleminin gerçekleþmesi lazým. Cookileri alýyor claimslere dönüþtürüyor.
            // Bu dönüþtürmenin her seferinde gerçekleþmesi için bunu yazýyoruz.
            services.AddScoped<IClaimsTransformation, ClaimProvider.ClaimProvider>();

            services.AddSession(options =>
            {
                options.IdleTimeout = TimeSpan.FromMinutes(30);
                // her bir oturum açtýðýmýzda sessionda bizim için bir id yaratýlýr. ÝD de cookide tutulur. 
                // session id cookide tutulur. session id üzerinden bilginin kime ait olduðu kaydedilir.
                options.Cookie.Name = "MainSession";

            });

            services.AddMvc();
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();

                // web uygulamamýzý çalýþtýrdýðýmýz zaman tarayýcý burdan refresh iþlemi gerçekleþtirmek için
                app.UseBrowserLink();
            }


            //else
            //{
            //    app.UseExceptionHandler("/Error");
            //    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
            //    app.UseHsts();
            //}

            //app.UseHttpsRedirection();
            //app.UseStaticFiles();

            //app.UseDeveloperExceptionPage();


            app.UseStatusCodePages();
            app.UseStaticFiles();


            
        

            app.UseRouting();

            app.UseAuthentication();
            app.UseAuthorization();
            app.UseSession();

            app.UseEndpoints(endpoints =>
            {

                endpoints.MapControllerRoute(
                    name: "default",
                    pattern: "{controller=Home}/{action=Index}/{id?}");
            });
        }
    }
}
