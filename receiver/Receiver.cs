using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace receiver
{
    public class Receiver
    {
        public static void ExecuteClient()
        {
            Console.WriteLine("---RECEIVER APPLICATION---");
            try
            {
                IPHostEntry ipHost = Dns.GetHostEntry(Dns.GetHostName());
                IPAddress ipAddr = ipHost.AddressList[0];
                var serverEndpoint = new IPEndPoint(ipAddr, 22225);

                try
                {
                    while (true)
                    {
                        using var serverSocket = new Socket(ipAddr.AddressFamily, SocketType.Stream, ProtocolType.Tcp);

                        serverSocket.Connect(serverEndpoint);

                        var bytes = new byte[2048];

                        // Write data into the buffer.
                        serverSocket.Receive(bytes, 0, 2048, SocketFlags.None);

                        // Initalize arrays, which store lengths of the data.
                        byte[] messageLenBytes = new byte[4];
                        byte[] signatureLenBytes = new byte[4];
                        byte[] publicKeyLenBytes = new byte[4];

                        // Read the lengths of message, signature and public key.
                        using (var ms = new MemoryStream(bytes))
                        {
                            // Read the lengths.
                            ms.Seek(0, SeekOrigin.Begin);
                            ms.Read(messageLenBytes, 0, 3);
                            ms.Seek(4, SeekOrigin.Begin);
                            ms.Read(signatureLenBytes, 0, 3);
                            ms.Seek(8, SeekOrigin.Begin);
                            ms.Read(publicKeyLenBytes, 0, 3);

                            int messageLen = BitConverter.ToInt32(messageLenBytes, 0);
                            int signatureLen = BitConverter.ToInt32(signatureLenBytes, 0);
                            int publicKeyLen = BitConverter.ToInt32(publicKeyLenBytes, 0);

                            byte[] messageBytes = new byte[messageLen];
                            byte[] signatureBytes = new byte[signatureLen];
                            byte[] publicKeyBytes = new byte[publicKeyLen];

                            // Read the data.
                            ms.Seek(12, SeekOrigin.Begin);
                            ms.Read(messageBytes, 0, messageLen);
                            ms.Seek(12 + messageLen, SeekOrigin.Begin);
                            ms.Read(signatureBytes, 0, signatureLen);
                            ms.Seek(12 + messageLen + signatureLen, SeekOrigin.Begin);
                            ms.Read(publicKeyBytes, 0, publicKeyLen);


                            try
                            {
                                bool isValid = false;
                                using (var rsa = new RSACryptoServiceProvider())
                                {
                                    rsa.ImportRSAPublicKey(publicKeyBytes, out _);

                                    isValid = rsa.VerifyData(messageBytes, SHA1.Create(), signatureBytes);
                                }

                                var currentColor = Console.ForegroundColor;
                                Console.ForegroundColor = isValid ? ConsoleColor.Green : ConsoleColor.Red;
                                Console.WriteLine($"\n\n\n--THE MESSAGE IS {(isValid ? "VALID" : "INVALID")}!--");
                                Console.ForegroundColor = currentColor;
                            }
                            catch
                            {
                                var currentColor = Console.ForegroundColor;
                                Console.ForegroundColor = ConsoleColor.Red;
                                Console.WriteLine("\n\n\n--THE MESSAGE IS INVALID!--");
                                Console.ForegroundColor = currentColor;
                            }
                            Console.WriteLine($"\nMessage Received: {Encoding.UTF8.GetString(messageBytes)}");
                            Console.WriteLine($"\nBase64 Encoded Signature: {Convert.ToBase64String(signatureBytes)}");
                            Console.WriteLine($"\nUTF8 Encoded Signature: {Encoding.UTF8.GetString(signatureBytes)}");
                        }
                        serverSocket.Shutdown(SocketShutdown.Both);
                        serverSocket.Close();
                    }
                    
                }

                // Manage of Socket's Exceptions
                catch (ArgumentNullException ane)
                {

                    Console.WriteLine("ArgumentNullException : {0}", ane.ToString());
                }

                catch (SocketException se)
                {

                    Console.WriteLine("SocketException : {0}", se.ToString());
                }

                catch (Exception e)
                {
                    Console.WriteLine("Unexpected exception : {0}", e.ToString());
                }
            }

            catch (Exception e)
            {

                Console.WriteLine(e.ToString());
            }
        }
    }
}
