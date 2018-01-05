using System;

namespace ASPNETCore2JwtAuthentication.Common
{
    /// <summary>
    /// 守护 Extensions
    /// </summary>
    public static class GuardExtensions
    {
        /// <summary>
        /// 检查参数是否为空。
        /// </summary>
        public static void CheckArgumentIsNull(this object o, string name)
        {
            if (o == null)
                throw new ArgumentNullException(name);
        }
    }
}