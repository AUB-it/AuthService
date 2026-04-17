using AuthService.Models;
using ChatAppAPI.Token;
using Microsoft.AspNetCore.Mvc;

namespace AuthService.Controllers;

[ApiController]
[Route("[controller]")]
public class AuthController : ControllerBase
{
    private readonly ILogger<AuthController> _logger;
    private readonly TokenProvider _tokenProvider;

    public AuthController(TokenProvider tokenProvider, ILogger<AuthController> logger)
    {
        _logger = logger;
        _tokenProvider = tokenProvider;
    }
    
    [HttpPost]
    public IActionResult Authorize([FromBody]User user)
    {
        _logger.LogInformation($"Calling {nameof(Authorize)} endpoint for user: {user.GivenName}");
        var tokenString = _tokenProvider.Create(user);
        if (string.IsNullOrWhiteSpace(tokenString))
        {
            _logger.LogError($"{nameof(Authorize)} returned empty string");
            return Unauthorized();
        }
        _logger.LogInformation($"Returning JWT token for user: {user.GivenName}");
        return Ok(tokenString);
    }
}
