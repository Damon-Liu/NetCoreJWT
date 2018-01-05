using System;

namespace ASPNETCore2JwtAuthentication.DomainClasses
{
    public class UserToken
    {
        public int Id { get; set; }

        /// <summary>
        /// 访问令牌哈希值
        /// </summary>
        public string AccessTokenHash { get; set; }

        /// <summary>
        /// 访问令牌过期日期时间
        /// </summary>
        public DateTimeOffset AccessTokenExpiresDateTime { get; set; }

        /// <summary>
        /// 刷新令牌哈希值
        /// </summary>
        public string RefreshTokenIdHash { get; set; }

        /// <summary>
        /// 刷新令牌过期日期时间
        /// </summary>
        public DateTimeOffset RefreshTokenExpiresDateTime { get; set; }

        public int UserId { get; set; } // one-to-one association
        public virtual User User { get; set; }
    }
}