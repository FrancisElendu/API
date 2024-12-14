using API.Dtos;
using API.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Reflection.Metadata.Ecma335;

namespace API.Controllers
{
    [Authorize(Roles ="Admin")]  // if you have more than one role [Authorize(Roles ="Admin, User, Manager")]
    [Route("api/[controller]")]
    [ApiController]
    public class RolesController : ControllerBase
    {

        private readonly UserManager<AppUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IConfiguration _config;

        public RolesController(UserManager<AppUser> userManager, RoleManager<IdentityRole> roleManager, IConfiguration config)
        {
            _userManager = userManager ?? throw new ArgumentNullException(nameof(userManager));
            _roleManager = roleManager ?? throw new ArgumentNullException(nameof(roleManager));
            _config = config ?? throw new ArgumentNullException(nameof(config));
        }

        //api/roles
        [HttpPost()]
        public async Task<ActionResult<string>> CreateRole([FromBody] CreateRoleDto createRoleDto)
        {
            if(string.IsNullOrEmpty(createRoleDto.RoleName))
            {
                return BadRequest("Role name is required");
            }

            var roleExist = await _roleManager.RoleExistsAsync(createRoleDto.RoleName);

            if (roleExist) return BadRequest("Role already exist");
            var roleResult = await _roleManager.CreateAsync(new IdentityRole(createRoleDto.RoleName));

            if (roleResult.Succeeded) return Ok(new { message = "Role created successfully" });
            return BadRequest("Role creation failed");
        }


        [HttpGet()]
        public async Task<ActionResult<IEnumerable<RoleResponseDto>>> GetRoles()
        {
            return Ok(await _roleManager.Roles.Select(r => new RoleResponseDto
            {
                Id = r.Id,
                Name = r.Name,
                TotalUsers = _userManager.GetUsersInRoleAsync(r.Name!).Result.Count
            }).ToListAsync());
            //var roles = await _roleManager.Roles.Select(r => new RoleResponseDto
            //{
            //    Id = r.Id,
            //    Name = r.Name,
            //    TotalUsers = _userManager.GetUsersInRoleAsync(r.Name!).Result.Count
            //}).ToListAsync();

            //return Ok(roles);
        }

        [HttpDelete("{id}")]
        public async Task<IActionResult> DleletRole(string id)
        {
            //find role by id
            var role = await _roleManager.FindByIdAsync(id);
            if (role is null) return BadRequest("Role not found.");
             var result = await _roleManager.DeleteAsync(role);

            if (result.Succeeded) return Ok(new { message = "Role deleted successfully" });
            return BadRequest("Role deletion failed");
        }

        //api/roles/assign
        [HttpPost("assign")]
        public async Task<IActionResult> AssignRole([FromBody] RoleAssignDto roleAssignDto)
        {
            var user = await _userManager.FindByIdAsync(roleAssignDto.UserId);
            if (user is null) return NotFound("User not found");

            var role = await _roleManager.FindByIdAsync(roleAssignDto.RoleId);
            if (role is null) return NotFound("Role not found");

            var result = await _userManager.AddToRoleAsync(user, role.Name!);

            if (result.Succeeded) return Ok(new { message = "Role assigned successfully" });
            var error = result.Errors.FirstOrDefault();
            return BadRequest(error!.Description);

        }
    }
}
