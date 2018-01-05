using System;
using System.Collections.Generic;

namespace ASPNETCore2JwtAuthentication.DomainClasses
{
    public class User
    {
        public User()
        {
            UserRoles = new HashSet<UserRole>();
        }

        public int Id { get; set; }

        public string UserName { get; set; }

        public string Password { get; set; }

        public string DisplayName { get; set; }

        public bool IsActive { get; set; }

        public DateTimeOffset? LastLoggedIn { get; set; }

        /// <summary>
        /// 序列号
        /// </summary>
        public string SerialNumber { get; set; }

        public virtual ICollection<UserRole> UserRoles { get; set; }

        public virtual UserToken UserToken { get; set; }
    }
}
