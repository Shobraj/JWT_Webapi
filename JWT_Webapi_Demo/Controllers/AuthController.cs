using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.Extensions.Configuration;
using JWT_Webapi_Demo.Model;

namespace JWT_Webapi_Demo.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IConfiguration configuration;
        public AuthController(IConfiguration config)
        {
            configuration = config;
        }
        [HttpPost("token")]
        public ActionResult GetToken([FromBody]UserModel userModel)
        {
            if (userModel.Name == "admin" && userModel.Password == "admin") //Verify user details from db
            {
                //Security Key
                string securityKey = configuration["Jwt:securityKey"]; 

                //symmetric security key
                var symmetricSecurityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(securityKey));

                //signing credentials
                var signingCredentials = new SigningCredentials(symmetricSecurityKey, SecurityAlgorithms.HmacSha256Signature);

                //create token 
                var token = new JwtSecurityToken(
                    issuer: configuration["Jwt:issuer"],
                    audience: configuration["Jwt:audience"],
                    expires: DateTime.Now.AddHours(1),
                    signingCredentials: signingCredentials
                    );

                //return token
                return Ok(new JwtSecurityTokenHandler().WriteToken(token));
            }
            else
            {
                return NotFound();
            }

        }
    }
}