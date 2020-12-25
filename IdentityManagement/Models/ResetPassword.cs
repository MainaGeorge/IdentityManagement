using System.ComponentModel.DataAnnotations;

namespace IdentityManagement.Models
{
    public class ResetPassword
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; }   
    }
}
