using System;
using System.IO;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;
using Microsoft.Extensions.Configuration;

namespace ASPNETCore2JwtAuthentication.DataLayer.Context
{
    /// <summary>
    /// Only used by EF Tooling
    /// EF工具可以使用这个工厂来创建DbContext的一个实例
    /// </summary>
    public class ApplicationDbContextFactory : IDesignTimeDbContextFactory<ApplicationDbContext>
    {
        public ApplicationDbContext CreateDbContext(string[] args)
        {
            var basePath = Directory.GetCurrentDirectory();
            Console.WriteLine($"Using `{basePath}` as the BasePath");
            var configuration = new ConfigurationBuilder()
                                    .SetBasePath(basePath)
                                    .AddJsonFile("appsettings.json")
                                    .Build();
            var builder = new DbContextOptionsBuilder<ApplicationDbContext>();
            var connectionString = configuration.GetConnectionString("DefaultConnection");
            builder.UseSqlServer(connectionString);
            return new ApplicationDbContext(builder.Options);
        }
    }
}