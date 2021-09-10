using Catel;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using MvcAuthenticationExample.Models;
using MvcAuthenticationExample.Utils;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.IO;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace MvcAuthenticationExample.Controllers.Api {
    [Route("api/[controller]")]
    [ApiController]
    public class DataController : ControllerBase {

        private UserManager<IdentityUser> _userManager;
        private SignInManager<IdentityUser> _signInManager;
        private IConfiguration _configuration;

        public DataController(UserManager<IdentityUser> userManager, SignInManager<IdentityUser> signInManager, IConfiguration configuration) {
            _userManager = userManager;
            _signInManager = signInManager;
            _configuration = configuration;
        }

        [HttpGet]
        [Authorize] //Authorize funciona con un token de autenticacion, este token va en la cabecera de la peticion
        //Para los casos web no es necesario declarar un token siempre, identity implicitamente da una cookie al usuario, y el usuario en cada peticion la presenta.
        //Para los casos externos (postman u otro sistema) se debe generar un token y hay que hacer un metodo donde la api cree esa autenticacion.
        public async Task<IActionResult> Get() {
            return Ok(SampleData.Orders);
        }

        [AllowAnonymous]
        [HttpPost]
        public async Task<IActionResult> Post(ApiCredentials Login) {
            if (!ModelState.IsValid) return BadRequest(ModelState.Values.Select(x => x.Errors).ToList());          
            IdentityUser Usuario = await _userManager.FindByEmailAsync(Login.User);
            if (Usuario == null) return NotFound("Usuario no encontrado.");
            var checkPass = await _signInManager.CheckPasswordSignInAsync(Usuario, Login.Password, true);
            if (checkPass.Succeeded) {
                var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration.GetValue<string>("SecretKey")));
                var claims = new ClaimsIdentity();
                claims.AddClaim(new Claim(ClaimTypes.NameIdentifier, Login.User));
                var tokenDescriptor = new SecurityTokenDescriptor {
                    Subject = claims,
                    Expires = DateTime.UtcNow.AddHours(4),
                    SigningCredentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256Signature)
                };
                var tokenHandler = new JwtSecurityTokenHandler();
                var createdToken = tokenHandler.CreateToken(tokenDescriptor);
                string bearer_token = tokenHandler.WriteToken(createdToken);
                return Ok(bearer_token);
            } else {
                return Forbid();
            }
        }

    }
}
