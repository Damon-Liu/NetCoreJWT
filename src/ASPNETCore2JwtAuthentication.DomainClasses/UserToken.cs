using System;

namespace ASPNETCore2JwtAuthentication.DomainClasses
{
    public class UserToken
    {
        public int Id { get; set; }

        /// <summary>
        /// �������ƹ�ϣֵ
        /// </summary>
        public string AccessTokenHash { get; set; }

        /// <summary>
        /// �������ƹ�������ʱ��
        /// </summary>
        public DateTimeOffset AccessTokenExpiresDateTime { get; set; }

        /// <summary>
        /// ˢ�����ƹ�ϣֵ
        /// </summary>
        public string RefreshTokenIdHash { get; set; }

        /// <summary>
        /// ˢ�����ƹ�������ʱ��
        /// </summary>
        public DateTimeOffset RefreshTokenExpiresDateTime { get; set; }

        public int UserId { get; set; } // one-to-one association
        public virtual User User { get; set; }
    }
}