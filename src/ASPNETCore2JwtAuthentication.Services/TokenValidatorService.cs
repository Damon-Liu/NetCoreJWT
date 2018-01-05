using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using ASPNETCore2JwtAuthentication.Common;
using Microsoft.AspNetCore.Authentication.JwtBearer;

namespace ASPNETCore2JwtAuthentication.Services
{
    public interface ITokenValidatorService
    {
        /// <summary>
        /// Token 验证
        /// </summary>
        /// <param name="context"></param>
        /// <returns></returns>
        Task ValidateAsync(TokenValidatedContext context);
    }

    public class TokenValidatorService : ITokenValidatorService
    {
        private readonly IUsersService _usersService;
        private readonly ITokenStoreService _tokenStoreService;

        public TokenValidatorService(IUsersService usersService, ITokenStoreService tokenStoreService)
        {
            _usersService = usersService;
            _usersService.CheckArgumentIsNull(nameof(usersService));

            _tokenStoreService = tokenStoreService;
            _tokenStoreService.CheckArgumentIsNull(nameof(_tokenStoreService));
        }

        public async Task ValidateAsync(TokenValidatedContext context)
        {
            var userPrincipal = context.Principal;

            var claimsIdentity = context.Principal.Identity as ClaimsIdentity;
            if (claimsIdentity?.Claims == null || !claimsIdentity.Claims.Any())
            {
                context.Fail("这不是我们发布的令牌。 它没有 Claims.");
                return;
            }

            var serialNumberClaim = claimsIdentity.FindFirst(ClaimTypes.SerialNumber);
            if (serialNumberClaim == null)
            {
                context.Fail("这不是我们发布的令牌。 它没有 serial.");
                return;
            }

            var userIdString = claimsIdentity.FindFirst(ClaimTypes.UserData).Value;
            if (!int.TryParse(userIdString, out int userId))
            {
                context.Fail("T这不是我们发布的令牌。 它没有 user-id.");
                return;
            }

            var user = await _usersService.FindUserAsync(userId).ConfigureAwait(false);
            if (user == null || user.SerialNumber != serialNumberClaim.Value || !user.IsActive)
            {
                // user has changed his/her password/roles/stat/IsActive
                context.Fail("Token过期了 请重新登录.");
            }

            var accessToken = context.SecurityToken as JwtSecurityToken;
            if (accessToken == null || string.IsNullOrWhiteSpace(accessToken.RawData) ||
                !await _tokenStoreService.IsValidTokenAsync(accessToken.RawData, userId).ConfigureAwait(false))
            {
                context.Fail("无效的Token.");
                return;
            }

            //更新用户最后活跃时间
            await _usersService.UpdateUserLastActivityDateAsync(userId).ConfigureAwait(false);
        }
    }
}