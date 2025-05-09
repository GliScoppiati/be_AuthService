using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using AuthService.Data;
using Microsoft.EntityFrameworkCore;

namespace AuthService.Controllers;

[ApiController]
[Route("api/admin")]
[Authorize(Roles = "Admin")]
public class AdminController : ControllerBase
{
    private readonly AuthDbContext _context;

    public AdminController(AuthDbContext context)
    {
        _context = context;
    }

    [HttpGet("users")]
    public async Task<IActionResult> GetAllUsers()
    {
        var users = await _context.Users
            .Select(u => new {
                u.Id,
                u.Username,
                u.Email,
                u.IsAdmin,
                u.IsDeleted,
                u.CreatedAt,
                u.LastLogin
            })
            .ToListAsync();

        return Ok(users);
    }

    [HttpGet("users/{id}")]
    public async Task<IActionResult> GetUserById(Guid id)
    {
        var user = await _context.Users.FindAsync(id);
        if (user == null)
            return NotFound(new { error = "Utente non trovato." });

        return Ok(new {
            user.Id,
            user.Username,
            user.Email,
            user.IsAdmin,
            user.IsDeleted,
            user.CreatedAt,
            user.LastLogin
        });
    }

    [HttpDelete("users/{id}")]
    public async Task<IActionResult> DeleteUser(Guid id)
    {
        var user = await _context.Users.FindAsync(id);
        if (user == null)
            return NotFound(new { error = "Utente non trovato." });

        if (user.IsAdmin)
        {
            var totalAdmins = await _context.Users.CountAsync(u => u.IsAdmin && !u.IsDeleted);
            if (totalAdmins <= 1)
                return BadRequest(new { error = "Non puoi eliminare l'unico admin esistente." });
        }

        user.IsDeleted = true;
        if (!user.Email.StartsWith("[DELETED]"))
            user.Email = "[DELETED] " + user.Email;

        _context.Users.Update(user);
        await _context.SaveChangesAsync();

        return Ok(new { message = "Utente disattivato." });
    }

    [HttpGet("stats")]
    public async Task<IActionResult> GetStats()
    {
        var total = await _context.Users.CountAsync();
        var deleted = await _context.Users.CountAsync(u => u.IsDeleted);
        var admins = await _context.Users.CountAsync(u => u.IsAdmin);
        var recent = await _context.Users.CountAsync(u => u.CreatedAt >= DateTime.UtcNow.AddDays(-7));

        return Ok(new
        {
            totalUsers = total,
            deletedUsers = deleted,
            adminUsers = admins,
            registeredLast7Days = recent
        });
    }

    [HttpPost("force-logout/{userId}")]
    public async Task<IActionResult> ForceLogout(Guid userId)
    {
        var tokens = await _context.RefreshTokens
            .Where(t => t.UserId == userId)
            .ToListAsync();

        if (!tokens.Any())
            return NotFound(new { message = "Nessun token trovato per questo utente." });

        _context.RefreshTokens.RemoveRange(tokens);
        await _context.SaveChangesAsync();

        return Ok(new { message = "Utente disconnesso da tutte le sessioni." });
    }
}