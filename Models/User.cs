using System.ComponentModel.DataAnnotations;
using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;

namespace AuthService.Models;

public class User
{
    [BsonId]
    [BsonGuidRepresentation(GuidRepresentation.Standard)]
    public Guid Id { get; set; }

    [Required]
    public string Username { get; set; }
    
    [Required]
    public string Password { get; set; }
    [Required]
    public string GivenName { get; set; }

    [Required]
    public string FamilyName { get; set; }

    [Required]
    public string Address1 { get; set; }

    public string? Address2 { get; set; }
    
    [Required]
    public short PostalCode { get; set; }

    [Required]
    public string FaxNumber { get; set; }

    [Required]
    public string City { get; set; }

    [Required]
    public string Email { get; set; }

    [Required]
    public string Telephone { get; set; }
}