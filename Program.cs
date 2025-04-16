using AuthService.Data;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

// ▶️ Configura DbContext con PostgreSQL
builder.Services.AddDbContext<AuthDbContext>(options =>
    options.UseNpgsql(builder.Configuration.GetConnectionString("DefaultConnection")));

// 🔐 Configura impostazioni JWT
var jwtSettings = builder.Configuration.GetSection("Jwt");
var key = Encoding.ASCII.GetBytes(jwtSettings["Key"]!);
Console.WriteLine("CONNECTION STRING LETTA: " + builder.Configuration.GetConnectionString("DefaultConnection"));

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

// ▶️ Aggiunge i controller
builder.Services.AddControllers();

// 📚 Swagger + autorizzazione via bearer token
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new() { Title = "Auth API", Version = "v1" });

    c.AddSecurityDefinition("Bearer", new Microsoft.OpenApi.Models.OpenApiSecurityScheme
    {
        Description = @"JWT Authorization header usando lo schema Bearer.  
                        Inserisci 'Bearer' seguito da uno spazio e il tuo token.  
                        Esempio: Bearer 12345abcdef",
        Name = "Authorization",
        In = Microsoft.OpenApi.Models.ParameterLocation.Header,
        Type = Microsoft.OpenApi.Models.SecuritySchemeType.ApiKey,
        Scheme = "Bearer"
    });

    c.AddSecurityRequirement(new Microsoft.OpenApi.Models.OpenApiSecurityRequirement()
    {
        {
            new Microsoft.OpenApi.Models.OpenApiSecurityScheme
            {
                Reference = new Microsoft.OpenApi.Models.OpenApiReference
                {
                    Type = Microsoft.OpenApi.Models.ReferenceType.SecurityScheme,
                    Id = "Bearer"
                },
                Scheme = "oauth2",
                Name = "Bearer",
                In = Microsoft.OpenApi.Models.ParameterLocation.Header
            },
            new List<string>()
        }
    });
});

var app = builder.Build();

// 🔄 Migrazioni automatiche al boot con retry
using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
    var maxRetries = 10;
    var retries = 0;

    while (true)
    {
        try
        {
            db.Database.Migrate();
            Console.WriteLine("✅ Migration completata.");
            break;
        }
        catch (Exception ex)
        {
            retries++;
            Console.WriteLine($"⏳ Tentativo {retries}/10: il DB non è ancora pronto... {ex.Message}");

            if (retries >= maxRetries)
                throw;

            Thread.Sleep(2000);
        }
    }
}

// 🧱 Middleware pipeline
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();
app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();

Console.WriteLine("AuthService starting on: " + builder.Configuration["ASPNETCORE_URLS"]);
app.Run();

