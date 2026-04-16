using AuthService.Models;
using ChatAppAPI.Token;
using Microsoft.AspNetCore.Mvc;

namespace AuthService.Controllers;

[ApiController]
[Route("[controller]")]
public class AuthController : ControllerBase
{
    private readonly TokenProvider _tokenProvider;

    public AuthController(TokenProvider tokenProvider)
    {
        _tokenProvider = tokenProvider;
    }
    
    [HttpGet]
    public IActionResult Authorize([FromBody]LoginCredentials creds)
    {
        var tokenString = _tokenProvider.Create(creds.Username, creds.Password);
        if (string.IsNullOrWhiteSpace(tokenString))
            return Unauthorized();
        
        return Ok(tokenString);
    }
}
