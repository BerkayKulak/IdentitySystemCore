using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using IdentitySystemCore.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;

namespace IdentitySystemCore.ClaimProvider
{
    public class ClaimProvider : IClaimsTransformation
    {
        public UserManager<AppUser> userManager { get; set; }

        public ClaimProvider(UserManager<AppUser> userManager)
        {
            this.userManager = userManager;
        }

        // IdentityApi Arka tarafta Cookilerden gelen değerleri claimler oluştururken key , value şeklinde 
        // Bir tanede ben kendim dinamik olarak ekleyeceğim.
        public async Task<ClaimsPrincipal> TransformAsync(ClaimsPrincipal principal)
        {
            // kullanıcıı üye mi üye değil mi bunu tespit ediyoruz
            // authenticate bir kullanıcı mı
            if (principal != null && principal.Identity.IsAuthenticated)
            {
                // identity claimsleri artık elimizde var
                // benim kimliğim oluştu
                ClaimsIdentity identity = principal.Identity as ClaimsIdentity;

                // kullanıcıyı bulmam lazım
                AppUser user = await userManager.FindByNameAsync(identity.Name);

                if (user != null)
                {

                    if (user.City != null)
                    {
                        // city isimli bir claim yoksa
                        if (!principal.HasClaim(c => c.Type == "city"))
                        {

                            Claim cityClaim = new Claim("city", user.City, ClaimValueTypes.String, "Internal");

                            identity.AddClaim(cityClaim);
                        }
                    }


                }

            }


            return principal;
        }
    }
}
