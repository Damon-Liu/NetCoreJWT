using ASPNETCore2JwtAuthentication.DomainClasses;
using Microsoft.EntityFrameworkCore;

namespace ASPNETCore2JwtAuthentication.DataLayer.Context
{
    public class ApplicationDbContext : DbContext, IUnitOfWork
    {
        public ApplicationDbContext(DbContextOptions options) : base(options)
        { }

        public virtual DbSet<User> Users { set; get; }
        public virtual DbSet<Role> Roles { set; get; }
        public virtual DbSet<UserRole> UserRoles { get; set; }
        public virtual DbSet<UserToken> UserTokens { get; set; }

        protected override void OnModelCreating(ModelBuilder builder)
        {
            //应该放在这里，否则会改写下面的设置!
            base.OnModelCreating(builder);

            //自定义应用程序映射
            builder.Entity<User>(entity =>
            {
                entity.Property(e => e.UserName).HasMaxLength(450).IsRequired();
                entity.HasIndex(e => e.UserName).IsUnique();  //唯一的 索引
                entity.Property(e => e.Password).IsRequired();
                entity.Property(e => e.SerialNumber).HasMaxLength(450);
                entity.HasOne(e => e.UserToken)
                      .WithOne(ut => ut.User)
                      .HasForeignKey<UserToken>(ut => ut.UserId); // one-to-one
            });

            builder.Entity<Role>(entity =>
            {
                entity.Property(e => e.Name).HasMaxLength(450).IsRequired();
                entity.HasIndex(e => e.Name).IsUnique();
            });

            builder.Entity<UserRole>(entity =>
            {
                entity.HasKey(e => new { e.UserId, e.RoleId });
                entity.HasIndex(e => e.UserId);
                entity.HasIndex(e => e.RoleId);
                entity.Property(e => e.UserId);
                entity.Property(e => e.RoleId);
                entity.HasOne(d => d.Role).WithMany(p => p.UserRoles).HasForeignKey(d => d.RoleId);
                entity.HasOne(d => d.User).WithMany(p => p.UserRoles).HasForeignKey(d => d.UserId);
            });

            builder.Entity<UserToken>(entity =>
            {
            });
        }
    }
}