using Microsoft.Azure.KeyVault;
using Microsoft.Azure.KeyVault.Models;
using Microsoft.Azure.KeyVault.WebKey;
using Microsoft.IdentityModel.Clients.ActiveDirectory;
using Microsoft.Rest.Serialization;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace AzureKeyVaultHSMSigning
{
    class Program
    {
        static KeyVaultClient keyVaultClient;

        static void Main(string[] args)
        {
            KeyBundle keyBundle = null;
            var algorithm = JsonWebKeySignatureAlgorithm.RS256;

            //Execute CreateAzureVaultHSMKey.ps1 and get this values
            var keyName = "";
            var keyVaultAddress = "";
            var keyVersion = "";
            
            //Create a native app in Azure Active Directory and set the ApplicationId and a Key as client secret
            //Add this app to the access policy
            var applicationId = "";
            var clientSecret = "";

            keyVaultClient = new KeyVaultClient(new KeyVaultClient.AuthenticationCallback(
                   (authority, resource, scope) => GetAccessToken(authority, resource, applicationId, clientSecret)),
                   new HttpClient());

            Console.WriteLine("Paso 1: Obtener la llave \n\n");

            //Paso 1: Obten la llave
            keyBundle = GetKey(keyBundle, keyVersion, keyName, keyVaultAddress);

            Console.WriteLine("\n\nPaso 2: Firmar y Validar \n\n");

            //Paso 2: Firmar
            SignVerify(keyBundle, algorithm, "Texto a Firmar", keyVersion, keyName, keyVaultAddress);

            Console.ReadKey();

        }

        public static async Task<string> GetAccessToken(string authority, string resource, string clientId, string clientSecret)
        {
            var context = new AuthenticationContext(authority, TokenCache.DefaultShared);
            var clientCredentials = new ClientCredential(clientId, clientSecret);
            var result = await context.AcquireTokenAsync(resource, clientCredentials).ConfigureAwait(false);

            return result.AccessToken;
        }

        private static KeyBundle GetKey(KeyBundle key, string keyVersion, string keyName, string keyVaultAddress)
        {
            KeyBundle retrievedKey;
            retrievedKey = Task.Run(() => keyVaultClient.GetKeyAsync(keyVaultAddress, keyName, keyVersion)).ConfigureAwait(false).GetAwaiter().GetResult();

            Console.Out.WriteLine("Retrived key:---------------");
            PrintoutKey(retrievedKey);

            //store the created key for the next operation if we have a sequence of operations
            return retrievedKey;
        }

        private static void SignVerify(KeyBundle key, string algorithm, string textToSign, string keyVersion, string keyName, string keyVaultAddress)
        {
            KeyOperationResult signature;

            var bytes = Encoding.ASCII.GetBytes(textToSign);
            var hasher = new SHA256CryptoServiceProvider();
            var digest = hasher.ComputeHash(bytes);


            signature = Task.Run(() => keyVaultClient.SignAsync(keyVaultAddress, keyName, keyVersion, algorithm, digest)).ConfigureAwait(false).GetAwaiter().GetResult();

            Console.Out.WriteLine(string.Format(
                "The signature is created using key id {0} and algorithm {1} \n\t\n\t SIGNATURE: {2} ",
                signature.Kid, algorithm, Convert.ToBase64String(signature.Result)));

            // Verify the signature
            bool isVerified = Task.Run(() => keyVaultClient.VerifyAsync(signature.Kid, algorithm, digest, signature.Result)).ConfigureAwait(false).GetAwaiter().GetResult();

            Console.Out.WriteLine(string.Format("The signature is {0} verified!", isVerified ? "" : "not "));
        }


        private static void PrintoutKey(KeyBundle keyBundle)
        {
            Console.Out.WriteLine("Key: \n\tKey ID: {0}\n\tKey type: {1}\n\tJSON Web Key: {2}",
                keyBundle.Key.Kid, keyBundle.Key.Kty, keyBundle.Key.ToString());

            var expiryDateStr = keyBundle.Attributes.Expires.HasValue
                ? keyBundle.Attributes.Expires.ToString()
                : "Never";

            var notBeforeStr = keyBundle.Attributes.NotBefore.HasValue
                ? keyBundle.Attributes.NotBefore.ToString()
                : UnixTimeJsonConverter.EpochDate.ToString();

            Console.Out.WriteLine("Key attributes: \n\tIs the key enabled: {0}\n\tExpiry date: {1}\n\tEnable date: {2}",
                keyBundle.Attributes.Enabled, expiryDateStr, notBeforeStr);
        }

    }
}
