using System;

namespace ASPNETCore2JwtAuthentication.Common
{
    public static class DateTimeExtensions
    {
        /// <summary>
        /// ��Unix��Ԫ��1970��1��1�գ���ҹUTC��ת��Ϊ����
        /// </summary>
        /// <param name="date"></param>
        /// <returns></returns>
        public static long ToUnixEpochDate(this DateTime date)
            => (long)Math.Round((date.ToUniversalTime() -
             new DateTimeOffset(1970, 1, 1, 0, 0, 0, TimeSpan.Zero)).TotalSeconds);
    }
}