using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace IdentitySystemCore.Models
{
    public class AppIdentityDbContext : IdentityDbContext<AppUser,AppRole,string>
    {
        // IdentityDbContext'in ctoruna DbContextOptions<AppIdentityDbContext> değerini gönderdim.
        public AppIdentityDbContext(DbContextOptions<AppIdentityDbContext> options) : base(options)
        {

        }

    }
}
