using System;

namespace ASPNETCore2JwtAuthentication.Common
{
    public static class DateTimeExtensions
    {
        /// <summary>
        /// 自Unix纪元（1970年1月1日，午夜UTC）转换为秒数
        /// </summary>
        /// <param name="date"></param>
        /// <returns></returns>
        public static long ToUnixEpochDate(this DateTime date)
            => (long)Math.Round((date.ToUniversalTime() -
             new DateTimeOffset(1970, 1, 1, 0, 0, 0, TimeSpan.Zero)).TotalSeconds);
    }
}