using System;

namespace ASPNETCore2JwtAuthentication.Common
{
    /// <summary>
    /// �ػ� Extensions
    /// </summary>
    public static class GuardExtensions
    {
        /// <summary>
        /// �������Ƿ�Ϊ�ա�
        /// </summary>
        public static void CheckArgumentIsNull(this object o, string name)
        {
            if (o == null)
                throw new ArgumentNullException(name);
        }
    }
}