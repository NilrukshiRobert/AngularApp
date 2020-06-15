
using Microsoft.AspNetCore.Mvc;
using AngularApp.API.Data;
using System.Threading.Tasks;
using AngularApp.API.Models;
using AngularApp.API.Dtos;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using Microsoft.Extensions.Configuration;
using System;
using System.IdentityModel.Tokens.Jwt;

namespace AngularApp.API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IAuthRepository _repo;
        private readonly IConfiguration _config;
        public AuthController(IAuthRepository repo, IConfiguration config)
        {
            _config = config;
            _repo = repo;

        }

        [HttpPost("register")]

        public async Task<IActionResult> Register(UserForRegisterDto userForRegisterDto)
        {
            userForRegisterDto.Username = userForRegisterDto.Username.ToLower();
            if (await _repo.UserExist(userForRegisterDto.Username))
                return BadRequest("UserName already exist");

            var userToCreate = new User
            {
                Username = userForRegisterDto.Username
            };

            var createduser = await _repo.Register(userToCreate, userForRegisterDto.password);

            return StatusCode(201);
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login(UserForRegisterDto userForRegisterDto)
        {
            var userFromRepo = await _repo.Login(userForRegisterDto.Username, userForRegisterDto.password);

            if (userFromRepo == null)
                return Unauthorized();

            var claims = new[]
            {
                new Claim(ClaimTypes.NameIdentifier,userFromRepo.Id.ToString()),
                new Claim(ClaimTypes.Name,userFromRepo.Username)
            };

            var key = new SymmetricSecurityKey(Encoding.UTF8
            .GetBytes(_config.GetSection("AppSettings:Token").Value));

            var creds= new SigningCredentials(key,SecurityAlgorithms.HmacSha512Signature);
            var tokenDescriptor= new SecurityTokenDescriptor
            {
                Subject= new ClaimsIdentity(claims),
                Expires=DateTime.Now.AddDays(1),
                SigningCredentials= creds
            };

            var tokenHandler= new JwtSecurityTokenHandler();

            var token= tokenHandler.CreateToken(tokenDescriptor);
            
             return Ok(new {
               token= tokenHandler.WriteToken(token)

            });


       
        }
    }
}