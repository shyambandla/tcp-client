using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using System;
using System.Collections;
using System.Collections.Generic;
using UnityEngine;

public class BouncyCastleHashing
{
    private SecureRandom _cryptoRandom;

    public BouncyCastleHashing()
    {
        _cryptoRandom = new SecureRandom();
    }

    /// <summary>
    /// Random Salt Creation
    /// </summary>
    /// <param name="size">The size of the salt in bytes</param>
    /// <returns>A random salt of the required size.</returns>
    public byte[] CreateSalt(int size)
    {
        byte[] salt = new byte[size];
        _cryptoRandom.NextBytes(salt);
        return salt;
    }
    public string PBKDF2_SHA256_GetHash(string password, string saltAsBase64String, int iterations, int hashByteSize)
    {
        var saltBytes = Convert.FromBase64String(saltAsBase64String);

        var hash = PBKDF2_SHA256_GetHash(password, saltBytes, iterations, hashByteSize);

        return Convert.ToBase64String(hash);
    }

    /// <summary>
    /// Gets a PBKDF2_SHA256 Hash (CORE METHOD)
    /// </summary>
    /// <param name="password">The password as a plain text string</param>
    /// <param name="salt">The salt as a byte array</param>
    /// <param name="iterations">The number of times to encrypt the password</param>
    /// <param name="hashByteSize">The byte size of the final hash</param>
    /// <returns>A the hash as a byte array.</returns>
    public byte[] PBKDF2_SHA256_GetHash(string password, byte[] salt, int iterations, int hashByteSize)
    {
        var pdb = new Pkcs5S2ParametersGenerator(new Org.BouncyCastle.Crypto.Digests.Sha256Digest());
        pdb.Init(PbeParametersGenerator.Pkcs5PasswordToBytes(password.ToCharArray()), salt,
                     iterations);
        var key = (KeyParameter)pdb.GenerateDerivedMacParameters(hashByteSize * 8);
        return key.GetKey();
    }
    public bool ValidatePassword(string password, string salt, int iterations, int hashByteSize, string hashAsBase64String)
    {
        byte[] saltBytes = Convert.FromBase64String(salt);
        byte[] actualHashBytes = Convert.FromBase64String(hashAsBase64String);
        return ValidatePassword(password, saltBytes, iterations, hashByteSize, actualHashBytes);
    }

    /// <summary>
    /// Validates a password given a hash of the correct one (MAIN METHOD).
    /// </summary>
    /// <param name="password">The password to check.</param>
    /// <param name="correctHash">A hash of the correct password.</param>
    /// <returns>True if the password is correct. False otherwise.</returns>
    public bool ValidatePassword(string password, byte[] saltBytes, int iterations, int hashByteSize, byte[] actualGainedHasAsByteArray)
    {
        byte[] testHash = PBKDF2_SHA256_GetHash(password, saltBytes, iterations, hashByteSize);
        return SlowEquals(actualGainedHasAsByteArray, testHash);
    }

    private bool SlowEquals(byte[] a, byte[] b)
    {
        uint diff = (uint)a.Length ^ (uint)b.Length;
        for (int i = 0; i < a.Length && i < b.Length; i++)
            diff |= (uint)(a[i] ^ b[i]);
        return diff == 0;
    }

}