using System.ComponentModel.DataAnnotations;

namespace IdentityManagement.Models
{
    public class ConfirmEmail
    {
        [Required]
        public string UserId { get; set; }

        [Required]
        public string Token { get; set; }
    }
}
