using System.ComponentModel.DataAnnotations;

namespace AuthService.Models
{
    public class LogoutRequest
    {
        [Required]
        public string RefreshToken { get; set; } = string.Empty;
    }
}
