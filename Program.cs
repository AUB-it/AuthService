using System.Text;
using ChatAppAPI.Token;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using VaultSharp;
using VaultSharp.V1.AuthMethods.Token;
using VaultSharp.V1.AuthMethods;
using VaultSharp.V1.Commons;

var EndPoint = "https://localhost:8201/";
var httpClientHandler = new HttpClientHandler();
httpClientHandler.ServerCertificateCustomValidationCallback =
    (message, cert, chain, sslPolicyErrors) => { return true; };
    
// Initialize one of the several auth methods.
IAuthMethodInfo authMethod =
    new TokenAuthMethodInfo("00000000-0000-0000-0000-000000000000");
// Initialize settings. You can also set proxies, custom delegates etc. here.
var vaultClientSettings = new VaultClientSettings(EndPoint, authMethod)
{
    Namespace = "",
    MyHttpClientProviderFunc = handler
        => new HttpClient(httpClientHandler) {
            BaseAddress = new Uri(EndPoint)
        }
};
IVaultClient vaultClient = new VaultClient(vaultClientSettings);
string jwtSecretString = "";
try
{
    Secret<SecretData> jwtSecret = await vaultClient.V1.Secrets.KeyValue.V2
        .ReadSecretAsync(path: "authSecrets", mountPoint: "secret");
    jwtSecretString = (string)jwtSecret.Data.Data["JWT_SECRET"];
}
catch (Exception e)
{
    Console.WriteLine("Noget gik galt: " + e.InnerException.Message);
}

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

builder.Services.AddControllers();
// Learn more about configuring OpenAPI at https://aka.ms/aspnet/openapi
builder.Services.AddOpenApi();

builder.Services.AddSingleton<TokenProvider>();

builder.Services.AddAuthorization();
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(o =>
    {
        o.RequireHttpsMetadata = false;
        o.TokenValidationParameters = new TokenValidationParameters()
        {
            IssuerSigningKey =
                new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSecretString)),
            ValidIssuer = builder.Configuration["Jwt:Issuer"],
            ValidAudience = builder.Configuration["Jwt:Audience"],
            ClockSkew = TimeSpan.Zero,
        };
    });

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
}

app.UseHttpsRedirection();

app.UseAuthorization();

app.MapControllers();

app.Run();
