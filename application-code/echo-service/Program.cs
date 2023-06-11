using System;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;
using Amazon.CognitoIdentityProvider;
using Amazon.CognitoIdentityProvider.Model;
using Newtonsoft.Json;
using System.Collections.Generic;
using System.Net.Http.Headers;

namespace EchoService
{
    class Program
    {
        private static readonly AmazonCognitoIdentityProviderClient _cognitoClient = new AmazonCognitoIdentityProviderClient();

        static async Task Main(string[] args)
        {
            var listener = new TcpListener(IPAddress.Any, 3000);
            listener.Start();
            Console.WriteLine("Listening on port 3000...");
            while (true)
            {
                var client = await listener.AcceptTcpClientAsync();
                var stream = client.GetStream();
                var buffer = new byte[1024];
                var bytesRead = await stream.ReadAsync(buffer, 0, buffer.Length);
                var message = Encoding.ASCII.GetString(buffer, 0, bytesRead);
                Console.WriteLine("Received message: {0}", message);

                // Check if the request contains an Authorization header
                if (!message.Contains("Authorization: Basic"))
                {
                    Console.WriteLine("Unauthorized request");
                    var response = Encoding.ASCII.GetBytes("HTTP/1.1 200 OK\r\n\r\n");
                    await stream.WriteAsync(response, 0, response.Length);
                    client.Close();
                    continue;
                }

                var authHeader = message.Split("Authorization: Basic")[1].Split("\n")[0].Trim();
                var authHeaderBytes = Convert.FromBase64String(authHeader);
                var authDetails = Encoding.ASCII.GetString(authHeaderBytes).Split(":");
                var username = authDetails[0];
                var password = authDetails[1];

            var validateTokenRequest = new AdminInitiateAuthRequest
            {
                UserPoolId = Environment.GetEnvironmentVariable("COGNITO_USER_POOL_ID"),
                ClientId = Environment.GetEnvironmentVariable("COGNITO_USER_POOL_CLIENT_ID"),
                AuthFlow = AuthFlowType.ADMIN_NO_SRP_AUTH,
                AuthParameters = new Dictionary<string, string>
                {
                    { "USERNAME", username },
                    { "PASSWORD", password }
                }
            };


                var validateTokenResponse = await _cognitoClient.AdminInitiateAuthAsync(validateTokenRequest);

                if (validateTokenResponse.ChallengeName == ChallengeNameType.NEW_PASSWORD_REQUIRED)
                {
                    var response = Encoding.ASCII.GetBytes("HTTP/1.1 403 Forbidden\r\n\r\nPassword reset required");
                    stream.Write(response, 0, response.Length);
                    client.Close();
                    continue;
                }

                if (validateTokenResponse.AuthenticationResult == null)
                {
                    var response = Encoding.ASCII.GetBytes("HTTP/1.1 403 Forbidden\r\n\r\nInvalid credentials");
                    stream.Write(response, 0, response.Length);
                    client.Close();
                    continue;
                }

                var userInfoRequest = new GetUserRequest
                {
                    AccessToken = validateTokenResponse.AuthenticationResult.AccessToken
                };

                var userInfoResponse = await _cognitoClient.GetUserAsync(userInfoRequest);

                var responseBody = new Dictionary<string, string>
                {
                    { "message", "Hello, " + userInfoResponse.Username },
                    { "email", userInfoResponse.UserAttributes.FirstOrDefault(a => a.Name == "email")?.Value }
                };

                var responseJson = JsonConvert.SerializeObject(responseBody);
                var responseBytes = Encoding.ASCII.GetBytes("HTTP/1.1 200 OK\r\n\r\n" + responseJson);
                stream.Write(responseBytes, 0, responseBytes.Length);
                client.Close();

            }
        }
    }
}

