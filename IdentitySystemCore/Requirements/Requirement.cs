using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;

namespace IdentitySystemCore.Requirements
{
    // içerisinde 30 günlük verinin kontrol edildiği bir sınıf
    public class ExpireDateExchangeRequirement : IAuthorizationRequirement
    {

    }

    public class ExpireDateExchangeHandler : AuthorizationHandler<ExpireDateExchangeRequirement>
    {
        protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, ExpireDateExchangeRequirement requirement)
        {

            if (context.User != null && context.User.Identity != null)
            {
                // böyle bir claim var mı kontrol ediyoruz. ben bu değerle tarihi karşılaştıracağım
                var claim = context.User.Claims.Where(x => x.Type == "ExpireDateExchange" && x.Value != null).FirstOrDefault();

                if (claim != null)

                {
                    if (DateTime.Now < Convert.ToDateTime(claim.Value))
                    {
                        context.Succeed(requirement);
                    }
                    else
                    {
                        // kulanıcı 30 gün sonra buraya erişmeye çalışırsa fail olacak
                        context.Fail();
                    }
                }
            }

            return Task.CompletedTask;
        }
    }
}
