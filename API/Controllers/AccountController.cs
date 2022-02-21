using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using API.Data;
using API.DTOs;
using API.Entities;
using API.Interfaces;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace API.Controllers
{
    public class AccountController : BaseAPIController
    {
        private readonly DataContext _context;
        private readonly ITokenService _tokenService;
        public AccountController(DataContext context, ITokenService tokenService)
        {
            _tokenService = tokenService;
            _context = context;
        }

        [HttpPost("register")]
        public async Task<ActionResult<UserDTO>> Register(RegisterDTO userdto)
        {
            if ( await UserExists(userdto.Username)) return BadRequest("User name already exists");
            using var hmac= new HMACSHA512();
            var user = new AppUser
            {
                UserName= userdto.Username.ToLower(),
                PasswordHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(userdto.Password)),
                PasswordSalt= hmac.Key
            };

            _context.Users.Add(user);
            await _context.SaveChangesAsync();
            return new UserDTO {
                Username= userdto.Username,
                Token= _tokenService.createToken(user)
            };
        }

        [HttpPost("login")]
        public async Task<ActionResult<UserDTO>> Login(LoginDTO logindto)
        {
            var user = _context.Users.SingleOrDefault(x => x.UserName == logindto.Username);
            if (user == null) return Unauthorized("User does not exist");

            using var hmac= new HMACSHA512(user.PasswordSalt);
            var pHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(logindto.Password));
            for(int i=0; i< pHash.Length; i++)
            {
                if(pHash[i] != user.PasswordHash[i]) return Unauthorized("Invalid Password");
            }
            
            return new UserDTO {
                Username= logindto.Username,
                Token=  _tokenService.createToken(user)
            };
        }

        private async Task<bool> UserExists(string username)
        {
            return await _context.Users.AnyAsync(x => x.UserName == username.ToLower());
        }
    }
}