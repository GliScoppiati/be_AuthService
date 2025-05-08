using System.Net.Http.Json;
using System.Text.Json.Serialization;

namespace AuthService.Services;

public class UserProfileClient
{
    private readonly HttpClient _http;

    public UserProfileClient(HttpClient http)
    {
        _http = http;
    }

    public async Task<UserProfileResponse> GetUserProfileAsync(Guid userId)
    {
        var profile = await _http.GetFromJsonAsync<UserProfileResponse>($"api/userprofile/{userId}");

        return profile ?? new UserProfileResponse
        {
            AlcoholAllowed = false,
            ConsentProfiling = false
        };
    }

    public class UserProfileResponse
    {
        [JsonPropertyName("alcoholAllowed")]
        public bool AlcoholAllowed { get; set; }
        [JsonPropertyName("consentProfiling")]
        public bool ConsentProfiling { get; set; }
    }
}
