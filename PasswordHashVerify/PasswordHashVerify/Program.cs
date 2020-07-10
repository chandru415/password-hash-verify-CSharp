using Microsoft.AspNetCore.Cryptography.KeyDerivation;
using System;
using System.Security.Cryptography;

namespace PasswordHashVerify
{
    static class Program
    {
        static void Main(string[] args)
        {
            Console.Write("Enter a password: ");
            string password = Console.ReadLine();

            var generatedHashPasssword = GenerateHashPassword(password);
            Console.ReadLine();
        }

        private static string GenerateHashPassword(string password, byte[] salt = null, bool needsOnlyHash = false)
        {
            if (salt == null || salt.Length != 16)
            {
                // generate a 128-bit salt using a secure PRNG
                salt = new byte[128 / 8];
                using (var rng = RandomNumberGenerator.Create())
                {
                    rng.GetBytes(salt);
                }
            }

            string hashed = Convert.ToBase64String(KeyDerivation.Pbkdf2(
                password: password,
                salt: salt,
                prf: KeyDerivationPrf.HMACSHA256,
                iterationCount: 10000,
                numBytesRequested: 256 / 8));

            if (needsOnlyHash) return hashed;
            Console.WriteLine($"salt: {Convert.ToBase64String(salt)}");
            Console.WriteLine($"hashed: {hashed}");
            // password will be concatenated with salt using ':'
            return $"{hashed}:{Convert.ToBase64String(salt)}";
        }


    }
}
