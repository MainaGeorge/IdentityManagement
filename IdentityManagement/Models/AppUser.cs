using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Identity;

namespace IdentityManagement.Models
{
    public class AppUser : IdentityUser
    {
        [Required]
        public string Name { get; set; }    
    }
}
