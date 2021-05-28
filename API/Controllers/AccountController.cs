using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using API.Data;
using API.Entities;
using Microsoft.AspNetCore.Mvc;
using API.DTOs;
using Microsoft.EntityFrameworkCore;
using API.Interfaces;

namespace API.Controllers
{
    public class AccountController : BaseApiController
    {
        private readonly DataContext _context;

        private readonly ITokenService _tokenService;

        public AccountController(DataContext context, ITokenService tokenService)
        {
            _context = context;
            _tokenService = tokenService;
        }

        [HttpPost("register")]
        public async Task <ActionResult<UserDTO>> Register(RegisterDTO registerDTO){
            
            if (await UserExists(registerDTO.Username)) return BadRequest("Username ya existe");

            using var hmac = new HMACSHA512 ();
            var user = new AppUser {

                UserName = registerDTO.Username.ToLower(),
                PasswordHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(registerDTO.Password)),
                PasswordSalt = hmac.Key
            };

          _context.Users.Add(user);
          await _context.SaveChangesAsync();

          return new UserDTO {

              Username = user.UserName,
              Token = _tokenService.CreateToken (user)
          };

        }

        [HttpPost("login")]
        public async Task <ActionResult<AppUser>> Login(LoginDTO loginDTO){

            var user = await _context.Users.SingleOrDefaultAsync(user => user.UserName == loginDTO.Username);

            if(user == null) return Unauthorized ("Usuario invalido");

            using var hmac = new HMACSHA512 (user.PasswordSalt);
            var ComputeHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(loginDTO.Password));

            for(int i = 0; i < ComputeHash.Length; i++){

                if (ComputeHash[i] != user.PasswordHash[i]) return Unauthorized ("Password invalido");
            }

            return user;

        }


        private async Task<bool> UserExists(string username){

            return await _context.Users.AnyAsync(variable => variable.UserName == username.ToLower());

        }
    }
}