using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;




namespace aes_example
{
    using System;
    using System.IO;
    using System.Security.Cryptography;

    class Program
    {
        public const int SALT_SIZE = 16; // size in bytes
        public const int HASH_SIZE = 32; // size in bytes
        public const int ITERATIONS = 100000; // number of pbkdf2 iterations


        public static byte[] GetSalt()
        {
            RNGCryptoServiceProvider provider = new RNGCryptoServiceProvider();
            byte[] salt = new byte[SALT_SIZE];
            provider.GetBytes(salt);
            return salt;
        }
        public static byte[] CreateHash(string input,byte[] salt)
        {
            // Generate a salt
           

            // Generate the hash
            Rfc2898DeriveBytes pbkdf2 = new Rfc2898DeriveBytes(input, salt, ITERATIONS, HashAlgorithmName.SHA256);
            return pbkdf2.GetBytes(HASH_SIZE);
        }
        public static void Main()
        {
            try
            {

                string original = "Here is some data to encrypt!";

                // Create a new instance of the Aes 
                // class.  This generates a new key and initialization  
                // vector (IV). 
                using (var random = new RNGCryptoServiceProvider())
                {
                    var key = new byte[16];
                    random.GetBytes(key);
                    var salt=new byte[SALT_SIZE];
                    salt=GetSalt();
                    key=CreateHash("hello shyam",salt);
                    // Encrypt the string to an array of bytes. 
                    byte[] encrypted = EncryptStringToBytes_Aes(original, key,salt);

                    // Decrypt the bytes to a string. 
                    string roundtrip = DecryptStringFromBytes_Aes(encrypted, key);

                    //Display the original data and the decrypted data.
                    Console.WriteLine("Original:   {0}", Convert.ToBase64String(key));
                    Console.WriteLine("Original:   {0}", original);
                    Console.WriteLine("Encrypted (b64-encode): {0}", Convert.ToBase64String(encrypted));
                    Console.WriteLine("Round Trip: {0}", roundtrip);
                    Console.ReadKey();
                }

            }
            catch (Exception e)
            {
                Console.WriteLine("Error: {0}", e.Message);
            }
        }

        static byte[] EncryptStringToBytes_Aes(string plainText, byte[] Key,byte[] salt)
        {
            byte[] encrypted;
            byte[] IV;

            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Key;

                aesAlg.GenerateIV();
                IV = aesAlg.IV;

                aesAlg.Mode = CipherMode.CBC;

                var encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                // Create the streams used for encryption. 
                using (var msEncrypt = new MemoryStream())
                {
                    using (var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (var swEncrypt = new StreamWriter(csEncrypt))
                        {
                            //Write all data to the stream.
                            swEncrypt.Write(plainText);
                        }
                        encrypted = msEncrypt.ToArray();
                    }
                }
            }

            var combinedIvCt = new byte[salt.Length+IV.Length + encrypted.Length];
            Array.Copy(salt, 0, combinedIvCt, 0, salt.Length);
            Array.Copy(IV, 0, combinedIvCt, salt.Length, IV.Length);
            Array.Copy(encrypted, 0, combinedIvCt, IV.Length+salt.Length, encrypted.Length);
            Console.WriteLine(Convert.ToBase64String(combinedIvCt));
            // Return the encrypted bytes from the memory stream. 
            return combinedIvCt;

        }

        static string DecryptStringFromBytes_Aes(byte[] cipherTextCombined, byte[] Key)
        {

            // Declare the string used to hold 
            // the decrypted text. 
            string plaintext = null;

            // Create an Aes object 
            // with the specified key and IV. 
            using (Aes aesAlg = Aes.Create())
            {
               

                byte[] IV = new byte[aesAlg.BlockSize / 8];
                byte[] salt= new byte[16];
                byte[] cipherText = new byte[cipherTextCombined.Length - (IV.Length+salt.Length)];
               



               
                
                Array.Copy(cipherTextCombined, salt, salt.Length);
                Array.Copy(cipherTextCombined, salt.Length, IV, 0, IV.Length);
                Array.Copy(cipherTextCombined, IV.Length+salt.Length, cipherText, 0, cipherText.Length);
                Console.WriteLine(Convert.ToBase64String(salt));
                Console.WriteLine(Convert.ToBase64String(IV));
                aesAlg.Key = CreateHash("hello shyam",salt);
                aesAlg.IV = IV;

                aesAlg.Mode = CipherMode.CBC;

                // Create a decrytor to perform the stream transform.
                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                // Create the streams used for decryption. 
                using (var msDecrypt = new MemoryStream(cipherText))
                {
                    using (var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (var srDecrypt = new StreamReader(csDecrypt))
                        {

                            // Read the decrypted bytes from the decrypting stream
                            // and place them in a string.
                            plaintext = srDecrypt.ReadToEnd();
                        }
                    }
                }

            }

            return plaintext;

        }
    }
}
