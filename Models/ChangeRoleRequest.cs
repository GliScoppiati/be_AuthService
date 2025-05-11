using System.ComponentModel.DataAnnotations;

namespace AuthService.Models
{
    public class ChangeRoleRequest
    {
        [Required]
        public Guid TargetUserId { get; set; }

        [Required]
        public bool MakeAdmin { get; set; }
    }
}
