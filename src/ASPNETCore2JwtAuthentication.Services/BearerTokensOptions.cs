namespace ASPNETCore2JwtAuthentication.Services
{
    public class BearerTokensOptions
    {
        public string Key { set; get; }
        /// <summary>
        /// Token颁发机构
        /// </summary>
        public string Issuer { set; get; }
        /// <summary>
        /// 颁发给谁
        /// </summary>
        public string Audience { set; get; }
        /// <summary>
        /// 访问令牌过期分钟
        /// </summary>
        public int AccessTokenExpirationMinutes { set; get; }
        /// <summary>
        /// 刷新令牌过期分钟
        /// </summary>
        public int RefreshTokenExpirationMinutes { set; get; }
    }
}