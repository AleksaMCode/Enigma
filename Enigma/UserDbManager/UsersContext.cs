using System.Data.Entity;
using System.Data.SQLite;

namespace Enigma.UserDbManager
{
    internal class UsersContext : DbContext
    {
        public DbSet<User> Users { get; set; }
        public UsersContext(string source) :
            base(
                new SQLiteConnection()
                {
                    ConnectionString = new SQLiteConnectionStringBuilder()
                    {
                        DataSource = source
                    }
                    .ConnectionString
                },
                true)
        {
            DbConfiguration.SetConfiguration(new SQLiteConfiguration());
        }
    }
}
