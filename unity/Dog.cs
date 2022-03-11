using System.Collections;
using System.Collections.Generic;
using UnityEngine;
using Shyam;
using System;
using Org.BouncyCastle.Crypto;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
public class Dog : MonoBehaviour
{
    // Start is called before the first frame update
    void Start()
    {
       Programm programm = new Programm();
        programm.Test();
    }

    // Update is called once per frame
    void Update()
    {
        
    }
    public void CreatePasswordHash_Single()
    {
        int iterations = 100000; // The number of times to encrypt the password - change this
        int saltByteSize = 16; // the salt size - change this
        int hashByteSize = 32; // the final hash - change this
        

        BouncyCastleHashing mainHashingLib = new BouncyCastleHashing();

        var password = "my password"; // That's really secure! :)

        byte[] saltBytes = mainHashingLib.CreateSalt(saltByteSize);
        string saltString = Convert.ToBase64String(saltBytes);

        string pwdHash = mainHashingLib.PBKDF2_SHA256_GetHash(password, saltString, iterations, hashByteSize);
        Debug.Log(pwdHash);
        var isValid = mainHashingLib.ValidatePassword(password, saltBytes, iterations, hashByteSize, Convert.FromBase64String(pwdHash));
        Debug.Log(isValid);
    }
}
