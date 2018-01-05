namespace ASPNETCore2JwtAuthentication.Services
{
    public class BearerTokensOptions
    {
        public string Key { set; get; }
        /// <summary>
        /// Token�䷢����
        /// </summary>
        public string Issuer { set; get; }
        /// <summary>
        /// �䷢��˭
        /// </summary>
        public string Audience { set; get; }
        /// <summary>
        /// �������ƹ��ڷ���
        /// </summary>
        public int AccessTokenExpirationMinutes { set; get; }
        /// <summary>
        /// ˢ�����ƹ��ڷ���
        /// </summary>
        public int RefreshTokenExpirationMinutes { set; get; }
    }
}