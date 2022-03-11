using System.Collections;
using System.Collections.Generic;
using UnityEngine;
using System;
using System.Linq;
using Shyam;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System;
using System.IO;
using System.Security.Cryptography;

public class Programm
{
    public const int SALT_SIZE = 16; // size in bytes
    public const int HASH_SIZE = 32; // size in bytes
    public const int ITERATIONS = 100000; // number of pbkdf2 iterations


    public  byte[] GetSalt()
    {
        RNGCryptoServiceProvider provider = new RNGCryptoServiceProvider();
        byte[] salt = new byte[SALT_SIZE];
        provider.GetBytes(salt);
        return salt;
    }
    public  byte[] CreateHash(string input, byte[] salt)
    {
        // Generate a salt

        BouncyCastleHashing bcHash=new BouncyCastleHashing();

      byte[] hash= bcHash.PBKDF2_SHA256_GetHash("my password",salt, ITERATIONS,32);
        // Generate the hash
        Debug.Log(hash);
        return hash;
    }
    public void Test()
    {
        try
        {

            string original = "run";

            // Create a new instance of the Aes 
            // class.  This generates a new key and initialization  
            // vector (IV). 
            using (var random = new RNGCryptoServiceProvider())
            {
                var key = new byte[32];
                random.GetBytes(key);
                var salt = new byte[SALT_SIZE];
                salt = GetSalt();
                key = CreateHash("halt", salt);
                // Encrypt the string to an array of bytes. 
                byte[] encrypted = EncryptStringToBytes_Aes(original, key, salt);

                // Decrypt the bytes to a string. 
                string roundtrip = DecryptStringFromBytes_Aes(encrypted, key);

                //Display the original data and the decrypted data.
              //  Debug.Log(Convert.ToBase64String(key));
               // Debug.Log( original);
               // Debug.Log(Convert.ToBase64String(encrypted));
                Debug.Log( roundtrip);
                
            }

        }
        catch (Exception e)
        {
            Debug.Log( e.Message);
        }
    }

     byte[] EncryptStringToBytes_Aes(string plainText, byte[] Key, byte[] salt)
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

        var combinedIvCt = new byte[salt.Length + IV.Length + encrypted.Length];
        Debug.Log(combinedIvCt.Length);
        Array.Copy(salt, 0, combinedIvCt, 0, salt.Length);
        Array.Copy(IV, 0, combinedIvCt, salt.Length, IV.Length);
        Array.Copy(encrypted, 0, combinedIvCt, IV.Length + salt.Length, encrypted.Length);
        Debug.Log(IV.Length);
        Debug.Log("Combined");
        Debug.Log(Convert.ToBase64String(combinedIvCt));
        // Return the encrypted bytes from the memory stream. 
        return combinedIvCt;

    }

     string DecryptStringFromBytes_Aes(byte[] cipherTextCombined, byte[] Key)
    {

        // Declare the string used to hold 
        // the decrypted text. 
        string plaintext = null;

        // Create an Aes object 
        // with the specified key and IV. 
        using (Aes aesAlg = Aes.Create())
        {


            byte[] IV = new byte[aesAlg.BlockSize / 8];
            byte[] salt = new byte[16];
            byte[] cipherText = new byte[cipherTextCombined.Length - (IV.Length + salt.Length)];






            Array.Copy(cipherTextCombined, salt, salt.Length);
            Array.Copy(cipherTextCombined, salt.Length, IV, 0, IV.Length);
            Array.Copy(cipherTextCombined, IV.Length + salt.Length, cipherText, 0, cipherText.Length);
          //  Debug.Log(Convert.ToBase64String(salt));
           // Debug.Log(Convert.ToBase64String(IV));
            aesAlg.Key = CreateHash("hello shyam", salt);
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
