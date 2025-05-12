using AuthService.Data;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using System.Text;
using AuthService.Services;

var builder = WebApplication.CreateBuilder(args);

// ▶️ Configura DbContext con PostgreSQL
builder.Services.AddDbContext<AuthDbContext>(options =>
    options.UseNpgsql(builder.Configuration.GetConnectionString("DefaultConnection")));

// 🔐 Configura impostazioni JWT
var jwtSettings = builder.Configuration.GetSection("Jwt");
var key = Encoding.ASCII.GetBytes(jwtSettings["Key"]!);

builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
{
    options.RequireHttpsMetadata = false;
    options.SaveToken = true;
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        ValidIssuer = jwtSettings["Issuer"],
        ValidAudience = jwtSettings["Audience"],
        IssuerSigningKey = new SymmetricSecurityKey(key)
    };
});

// 🌍 HttpClient per chiamare user-profile-service
builder.Services.AddHttpClient("UserProfileService", client =>
{
    client.BaseAddress = new Uri("http://user-profile-service:80/");
});

// 🌍 HttpClient specifico per UserProfileClient (inietta direttamente UserProfileClient nei controller)
builder.Services.AddHttpClient<UserProfileClient>(client =>
{
    client.BaseAddress = new Uri("http://user-profile-service:80/");
});

// ➡️ CORS Policy (consigliato per microservizi)
builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowAll", policy =>
    {
        policy.AllowAnyOrigin()
              .AllowAnyHeader()
              .AllowAnyMethod();
    });
});

// ▶️ Aggiunge i controller
builder.Services.AddControllers();

// 📚 Swagger + autorizzazione via bearer token
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new() { Title = "Auth API", Version = "v1" });

    c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Description = @"JWT Authorization header usando lo schema Bearer.  
                        Inserisci 'Bearer' seguito da uno spazio e il tuo token.  
                        Esempio: Bearer 12345abcdef",
        Name = "Authorization",
        In = ParameterLocation.Header,
        Type = SecuritySchemeType.ApiKey,
        Scheme = "Bearer"
    });

    c.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type = ReferenceType.SecurityScheme,
                    Id = "Bearer"
                },
                Scheme = "oauth2",
                Name = "Bearer",
                In = ParameterLocation.Header
            },
            new List<string>()
        }
    });
});

var app = builder.Build();

static string HashPassword(string password)
{
    using var sha256 = System.Security.Cryptography.SHA256.Create();
    var bytes = System.Text.Encoding.UTF8.GetBytes(password);
    var hash = sha256.ComputeHash(bytes);
    return Convert.ToBase64String(hash);
}

// 🔄 Esegue migrazione automatica
using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
    var config = scope.ServiceProvider.GetRequiredService<IConfiguration>();
    var logger = scope.ServiceProvider.GetRequiredService<ILogger<Program>>();

    var maxRetries = 10;
    var retries = 0;

    while (true)
    {
        try
        {
            db.Database.Migrate();
            logger.LogInformation("[AuthService] ✅ Migration completata.");

            var adminEmail = config["AdminUser:Email"];
            var adminUsername = config["AdminUser:Username"];
            var adminPassword = config["AdminUser:Password"];

            if (!string.IsNullOrEmpty(adminEmail) &&
                !string.IsNullOrEmpty(adminUsername) &&
                !string.IsNullOrEmpty(adminPassword))
            {
                var exists = db.Users.Any(u => u.Email == adminEmail);
                if (!exists)
                {
                    var passwordHash = HashPassword(adminPassword);

                    db.Users.Add(new AuthService.Models.User
                    {
                        Email = adminEmail,
                        Username = adminUsername,
                        PasswordHash = passwordHash,
                        IsAdmin = true,
                        LastLogin = DateTime.UtcNow
                    });

                    db.SaveChanges();
                    logger.LogInformation("[AuthService] 👑 Utente admin creato.");
                }
                else
                {
                    logger.LogInformation("[AuthService] 👤 Utente admin già esistente.");
                }
            }
            else
            {
                logger.LogWarning("[AuthService] ⚠️ Parametri AdminUser incompleti. Utente admin non creato.");
            }

            break;
        }
        catch (Exception ex)
        {
            retries++;
            logger.LogWarning(ex, "[AuthService] ⏳ Tentativo {Retry}/{MaxRetries}: il DB non è ancora pronto...", retries, maxRetries);

            if (retries >= maxRetries)
            {
                logger.LogCritical(ex, "[AuthService] ❌ Errore critico: raggiunto il numero massimo di tentativi ({MaxRetries})", maxRetries);
                throw;
            }

            Thread.Sleep(2000);
        }
    }
}

// ➡️ Pipeline
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseCors("AllowAll"); // 💡 ATTENZIONE: CORS PRIMA di Authentication
app.UseHttpsRedirection();
app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();

var loggerMain = app.Services.GetRequiredService<ILogger<Program>>();
loggerMain.LogInformation("[AuthService] ✅ AuthService avviato su: {Url}", builder.Configuration["ASPNETCORE_URLS"]);

app.Run();
