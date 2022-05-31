using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace sender
{
    public class Sender
    {


        public static void ExecuteClient()
        {
            try
            {
                var ipHost = Dns.GetHostEntry(Dns.GetHostName());
                var ipAddr = ipHost.AddressList[0];
                var serverEndpoint = new IPEndPoint(ipAddr, 11111);

                Console.WriteLine("---SENDER APPLICATION---\n");
                try
                {
                    while (true)
                    {
                        using var serverSocket = new Socket(ipAddr.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
                        serverSocket.Connect(serverEndpoint);

                        Console.Write("\nPlease enter your message\n::> ");
                        string message = (Console.ReadLine() ?? "");

                        // Get bytes of the message, signature and public key.
                        byte[] messageBytes = Encoding.UTF8.GetBytes(message);
                        byte[] signature = Array.Empty<byte>();
                        byte[] publicKey = Array.Empty<byte>();
                        using (var rsa = new RSACryptoServiceProvider(1024))
                        {
                            signature = rsa.SignData(messageBytes, SHA1.Create());
                            publicKey = rsa.ExportRSAPublicKey();
                        }

                        // Get bytes of message's, signature's and public key's lengths.
                        byte[] messageBytesLen = BitConverter.GetBytes(messageBytes.Length);
                        byte[] signatureLen = BitConverter.GetBytes(signature.Length);
                        byte[] publicKeyLen = BitConverter.GetBytes(publicKey.Length);


                        var ms = new MemoryStream();

                        // Write length bytes into the MemoryStream.
                        ms.Write(messageBytesLen, 0, 4);
                        ms.Write(signatureLen, 0, 4);
                        ms.Write(publicKeyLen, 0, 4);

                        // Write the actual data into the MemoryStream.
                        ms.Write(messageBytes);
                        ms.Write(signature);
                        ms.Write(publicKey);

                        ms.Flush();

                        // Send the data to Server Application.
                        serverSocket.Send(ms.ToArray());

                        Console.WriteLine("\nMessage signed and sent to the Server Application successfully!");

                        //serverSocket.Receive(Array.Empty<byte>());

                        serverSocket.Shutdown(SocketShutdown.Both);
                        serverSocket.Close();
                    }
                }
                catch (ArgumentNullException ane)
                {

                    Console.WriteLine($"ArgumentNullException : {ane}");
                }

                catch (SocketException se)
                {

                    Console.WriteLine($"SocketException : {se}");
                }

                catch (Exception e)
                {
                    Console.WriteLine($"Unexpected exception : {e}");
                }
            }

            catch (Exception e)
            {
                Console.WriteLine(e.ToString());
            }
        }
    }
}
