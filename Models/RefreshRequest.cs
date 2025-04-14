using System.ComponentModel.DataAnnotations;

namespace AuthService.Models
{
    public class RefreshRequest
    {
        [Required]
        public string RefreshToken { get; set; } = string.Empty;
    }
}
