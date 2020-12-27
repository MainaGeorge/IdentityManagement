using System.ComponentModel.DataAnnotations;

namespace IdentityManagement.Models
{
    public class ExternalLoginConfirmation
    {
        [EmailAddress]
        [Required]
        public string Email { get; set; }

        public string ExternalProviderDisplayName { get; set; } 

        [Required]
        public string Name { get; set; }
    }
}
