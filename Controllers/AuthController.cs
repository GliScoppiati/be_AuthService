using Microsoft.AspNetCore.Mvc;
using AuthService.Models;
using AuthService.Data;
using AuthService.Services;
using System.Security.Cryptography;
using Microsoft.EntityFrameworkCore;
using System.Text;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;
using Microsoft.AspNetCore.Authorization;
using System.Net.Http.Json;

namespace AuthService.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly AuthDbContext _context;
        private readonly IConfiguration _configuration;
        private readonly IHttpClientFactory _httpClientFactory;
        private readonly UserProfileClient _userProfileClient;

        public AuthController(AuthDbContext context, IConfiguration configuration, IHttpClientFactory httpClientFactory, UserProfileClient userProfileClient)
        {
            _context = context;
            _configuration = configuration;
            _httpClientFactory = httpClientFactory;
            _userProfileClient = userProfileClient;   // ✅ OK ORA!
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterRequest request)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            var exists = await _context.Users.AnyAsync(u => u.Email == request.Email && !u.IsDeleted);
            if (exists)
                return BadRequest(new { error = "Email già registrata." });

            var user = new User
            {
                Username = request.Username,
                Email = request.Email,
                PasswordHash = HashPassword(request.Password),
                LastLogin = DateTime.UtcNow
            };

            _context.Users.Add(user);
            await _context.SaveChangesAsync();

            // 🔗 Invio richiesta al microservizio UserProfileService
            var client = _httpClientFactory.CreateClient("UserProfileService");

            var profilePayload = new
            {
                userId = user.Id,
                firstName = "",
                lastName = "",
                birthDate = DateTime.UtcNow,
                alcoholAllowed = false,
                consentGdpr = false,
                consentProfiling = false
            };

            var response = await client.PostAsJsonAsync("api/userprofile", profilePayload);

            if (!response.IsSuccessStatusCode)
            {
                return StatusCode((int)response.StatusCode, "Registrazione utente avvenuta, ma creazione profilo fallita.");
            }

            return Ok(new
		{
    		message = "Registrazione completata.",
    		userId = user.Id
		});
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginRequest request)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            var user = await _context.Users.FirstOrDefaultAsync(u => u.Email == request.Email);
            if (user == null)
                return Unauthorized("Credenziali non valide.");
            
            if (user.IsDeleted)
                return Unauthorized("Account disattivato.");

            var hash = HashPassword(request.Password);
            if (user.PasswordHash != hash)
                return Unauthorized("Credenziali non valide.");

            user.LastLogin = DateTime.UtcNow;
            _context.Users.Update(user);

            var token = GenerateJwtToken(user);
            var refreshToken = new RefreshToken
            {
                Token = Guid.NewGuid().ToString(),
                ExpiryDate = DateTime.UtcNow.AddDays(7),
                UserId = user.Id
            };

            _context.RefreshTokens.Add(refreshToken);
            await _context.SaveChangesAsync();

            return Ok(new
            {
            	userId = user.Id,
                token,
                refreshToken = refreshToken.Token
            });
        }

        [HttpPost("refresh")]
        public async Task<IActionResult> Refresh([FromBody] RefreshRequest request)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            var stored = await _context.RefreshTokens
                .Include(r => r.User)
                .FirstOrDefaultAsync(r => r.Token == request.RefreshToken && r.ExpiryDate > DateTime.UtcNow);

            if (stored == null || stored.User == null)
                return Unauthorized("Refresh token non valido o scaduto.");
            
            if (stored.User.IsDeleted)
                return Unauthorized("Account disattivato.");

            stored.User.LastLogin = DateTime.UtcNow;
            _context.Users.Update(stored.User);

            _context.RefreshTokens.Remove(stored);

            var newJwt = GenerateJwtToken(stored.User);
            var newRefreshToken = new RefreshToken
            {
                Token = Guid.NewGuid().ToString(),
                ExpiryDate = DateTime.UtcNow.AddDays(7),
                UserId = stored.User.Id
            };

            _context.RefreshTokens.Add(newRefreshToken);
            await _context.SaveChangesAsync();

            return Ok(new
            {
                token = newJwt,
                refreshToken = newRefreshToken.Token
            });
        }

        [HttpPost("logout")]
        public async Task<IActionResult> Logout([FromBody] LogoutRequest request)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            var stored = await _context.RefreshTokens
                .FirstOrDefaultAsync(r => r.Token == request.RefreshToken);

            if (stored == null)
                return NotFound("Refresh token non trovato.");

            _context.RefreshTokens.Remove(stored);
            await _context.SaveChangesAsync();

            return Ok(new { message = "Logout completato. Refresh token invalidato." });
        }
	
        [HttpGet("exists/{id}")]
        public async Task<IActionResult> CheckUserExists(Guid id)
        {
                var exists = await _context.Users.AnyAsync(u => u.Id == id);
                return Ok(new { exists });
        }

        [Authorize]
        [HttpGet("me")]
        public IActionResult GetProfile()
        {
            var username = User.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Name)?.Value;
            var email = User.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Email)?.Value;

            return Ok(new
            {
                username,
                email
            });
        }

        private string GenerateJwtToken(User user)
        {
            var jwtSettings = _configuration.GetSection("Jwt");
            var key = Encoding.ASCII.GetBytes(jwtSettings["Key"]!);

            var profile = _userProfileClient.GetUserProfileAsync(user.Id).GetAwaiter().GetResult();

            // 🔐 1. Costruisci la lista di claim base
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
                new Claim(ClaimTypes.Email, user.Email),
                new Claim(ClaimTypes.Name, user.Username),
                new Claim("alcoholAllowed", profile.AlcoholAllowed.ToString()),
                new Claim("profilingAllowed", profile.ConsentProfiling.ToString())
            };

            // 🔐 2. Se l’utente è admin, aggiungi il claim di ruolo
            if (user.IsAdmin)
                claims.Add(new Claim(ClaimTypes.Role, "Admin"));

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(claims),
                Expires = DateTime.UtcNow.AddMinutes(double.Parse(jwtSettings["ExpireMinutes"]!)),
                Issuer = jwtSettings["Issuer"],
                Audience = jwtSettings["Audience"],
                SigningCredentials = new SigningCredentials(
                    new SymmetricSecurityKey(key),
                    SecurityAlgorithms.HmacSha256Signature)
            };

            var tokenHandler = new JwtSecurityTokenHandler();
            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }

        private string HashPassword(string password)
        {
            using var sha256 = SHA256.Create();
            var bytes = Encoding.UTF8.GetBytes(password);
            var hash = sha256.ComputeHash(bytes);
            return Convert.ToBase64String(hash);
        }

        [HttpDelete("{id}")]
        public async Task<IActionResult> DeleteUser(Guid id)
        {
            var user = await _context.Users.FindAsync(id);
            if (user == null)
                return NotFound(new { error = "Utente non trovato." });

            user.IsDeleted = true;

            if (!user.Email.StartsWith("[DELETED]"))
                user.Email = $"[DELETED] {user.Email}";

            var tokens = _context.RefreshTokens.Where(r => r.UserId == id);
            _context.RefreshTokens.RemoveRange(tokens);

            _context.Users.Update(user);
            await _context.SaveChangesAsync();

            return Ok(new { message = "Utente disattivato." });
        }

        [Authorize]
        [HttpPost("change-password")]
        public async Task<IActionResult> ChangePassword([FromBody] ChangePasswordRequest request)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            var userIdClaim = User.Claims.FirstOrDefault(c => c.Type == ClaimTypes.NameIdentifier);
            if (userIdClaim == null || !Guid.TryParse(userIdClaim.Value, out var userId))
                return Unauthorized("Token non valido.");

            var user = await _context.Users.FirstOrDefaultAsync(u => u.Id == userId);
            if (user == null || user.IsDeleted)
                return Unauthorized("Utente non valido o disattivato.");

            var currentHash = HashPassword(request.CurrentPassword);
            if (user.PasswordHash != currentHash)
                return BadRequest(new { error = "La password attuale non è corretta." });

 
            user.PasswordHash = HashPassword(request.NewPassword);
            _context.Users.Update(user);

          
            var tokens = _context.RefreshTokens.Where(r => r.UserId == userId);
            _context.RefreshTokens.RemoveRange(tokens);

            await _context.SaveChangesAsync();

            return Ok(new { message = "Password aggiornata. Tutte le sessioni sono state disconnesse." });
        }
    }
}
