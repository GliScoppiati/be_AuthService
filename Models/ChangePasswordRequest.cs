using System.ComponentModel.DataAnnotations;

namespace AuthService.Models
{
    public class ChangePasswordRequest
    {
        [Required]
        public string CurrentPassword { get; set; } = null!;

        [Required]
        [MinLength(6, ErrorMessage = "La nuova password deve avere almeno 6 caratteri.")]
        public string NewPassword { get; set; } = null!;
    }
}
