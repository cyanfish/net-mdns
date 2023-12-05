using Common.Logging;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Threading.Tasks;

namespace Makaretu.Dns
{
    /// <summary>
    ///   Performs the magic to send and receive datagrams over multicast
    ///   sockets.
    /// </summary>
    class MulticastClient : IDisposable
    {
        static readonly ILog log = LogManager.GetLogger(typeof(MulticastClient));

        /// <summary>
        ///   The port number assigned to Multicast DNS.
        /// </summary>
        /// <value>
        ///   Port number 5353.
        /// </value>
        public static readonly int MulticastPort = 5353;

        static readonly IPAddress MulticastAddressIp4 = IPAddress.Parse("224.0.0.251");
        static readonly IPAddress MulticastAddressIp6 = IPAddress.Parse("FF02::FB");
        static readonly IPEndPoint MdnsEndpointIp6 = new IPEndPoint(MulticastAddressIp6, MulticastPort);
        static readonly IPEndPoint MdnsEndpointIp4 = new IPEndPoint(MulticastAddressIp4, MulticastPort);

        readonly List<UdpClient> receivers;
        readonly ConcurrentDictionary<IPAddressAndNIC, UdpClient> senders = new ConcurrentDictionary<IPAddressAndNIC, UdpClient>();

        public event EventHandler<UdpReceiveResult> MessageReceived;

        public MulticastClient(bool useIPv4, bool useIpv6, IEnumerable<NetworkInterface> nics)
        {
            // Setup the receivers.
            receivers = new List<UdpClient>();

            UdpClient receiver4 = null;
            if (useIPv4)
            {
                receiver4 = new UdpClient(AddressFamily.InterNetwork);
                receiver4.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
                receiver4.Client.Bind(new IPEndPoint(IPAddress.Any, MulticastPort));
                receivers.Add(receiver4);
            }

            UdpClient receiver6 = null;
            if (useIpv6)
            {
                receiver6 = new UdpClient(AddressFamily.InterNetworkV6);
                receiver6.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
                receiver6.Client.Bind(new IPEndPoint(IPAddress.IPv6Any, MulticastPort));
                receivers.Add(receiver6);
            }

            // Get the IP addresses that we should send to.
            var addressesAndNics = nics
                .SelectMany(GetNetworkInterfaceLocalAddresses)
                .Where(a => (useIPv4 && a.Address.AddressFamily == AddressFamily.InterNetwork)
                    || (useIpv6 && a.Address.AddressFamily == AddressFamily.InterNetworkV6));
            foreach (var addressAndNic in addressesAndNics)
            {
                if (senders.Keys.Contains(addressAndNic))
                {
                    continue;
                }
                var address = addressAndNic.Address;

                var localEndpoint = new IPEndPoint(address, MulticastPort);
                var sender = new UdpClient(address.AddressFamily);
                try
                {
                    switch (address.AddressFamily)
                    {
                        case AddressFamily.InterNetwork:
                            receiver4.Client.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.AddMembership, new MulticastOption(MulticastAddressIp4, address));
                            sender.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
                            sender.Client.Bind(localEndpoint);
                            sender.Client.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.AddMembership, new MulticastOption(MulticastAddressIp4));
                            sender.Client.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.MulticastLoopback, true);
                            break;
                        case AddressFamily.InterNetworkV6:
                            receiver6.Client.SetSocketOption(SocketOptionLevel.IPv6, SocketOptionName.AddMembership, new IPv6MulticastOption(MulticastAddressIp6, address.ScopeId));
                            sender.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
                            sender.Client.Bind(localEndpoint);
                            sender.Client.SetSocketOption(SocketOptionLevel.IPv6, SocketOptionName.AddMembership, new IPv6MulticastOption(MulticastAddressIp6));
                            sender.Client.SetSocketOption(SocketOptionLevel.IPv6, SocketOptionName.MulticastLoopback, true);
                            break;
                        default:
                            throw new NotSupportedException($"Address family {address.AddressFamily}.");
                    }

                    receivers.Add(sender);
                    log.Debug($"Will send via {localEndpoint}");
                    if (!senders.TryAdd(addressAndNic, sender)) // Should not fail
                    {
                        sender.Dispose();
                    }
                }
                catch (SocketException ex) when (ex.SocketErrorCode == SocketError.AddressNotAvailable)
                {
                    // VPN NetworkInterfaces
                    sender.Dispose();
                }
                catch (Exception e)
                {
                    log.Error($"Cannot setup send socket for {address}: {e.Message}");
                    sender.Dispose();
                }
            }

            // Start listening for messages.
            foreach (var r in receivers)
            {
                Listen(r);
            }
        }

        public async Task SendAsync(byte[] message)
        {
            foreach (var sender in senders)
            {
                try
                {
                    var endpoint = sender.Key.Address.AddressFamily == AddressFamily.InterNetwork ? MdnsEndpointIp4 : MdnsEndpointIp6;
                    await sender.Value.SendAsync(
                            message, message.Length,
                            endpoint)
                        .ConfigureAwait(false);
                }
                catch (Exception e)
                {
                    log.Error($"Sender {sender.Key} failure: {e.Message}");
                    // eat it.
                }
            }
        }

        public async Task SendFilteredAsync(Message message)
        {
            foreach (var sender in senders)
            {
                try
                {
                    var endpoint = sender.Key.Address.AddressFamily == AddressFamily.InterNetwork ? MdnsEndpointIp4 : MdnsEndpointIp6;
                    var serializedMessage = GetFilteredMessage(message, sender.Key.Interface);
                    await sender.Value.SendAsync(
                            serializedMessage, serializedMessage.Length,
                            endpoint)
                        .ConfigureAwait(false);
                }
                catch (Exception e)
                {
                    log.Error($"Sender {sender.Key} failure: {e.Message}");
                    // eat it.
                }
            }
        }

        private byte[] GetFilteredMessage(Message msg, NetworkInterface networkInterface)
        {
            var hostName = msg.AdditionalRecords.Concat(msg.Answers).OfType<AddressRecord>().Select(record => record.Name).FirstOrDefault();
            if (hostName == null)
            {
                return msg.ToByteArray();
            }

            var allAdditional = msg.AdditionalRecords.ToList();
            var allAnswers = msg.Answers.ToList();

            try
            {
                var nicAddresses = networkInterface.GetIPProperties().UnicastAddresses.Select(a => a.Address).ToList();
                if (msg.AdditionalRecords.RemoveAll(record => record is AddressRecord) > 0)
                {
                    foreach (var addr in nicAddresses)
                    {
                        msg.AdditionalRecords.Add(AddressRecord.Create(hostName, addr));
                    }
                }
                if (msg.Answers.RemoveAll(record => record is AddressRecord) > 0)
                {
                    foreach (var addr in nicAddresses)
                    {
                        msg.Answers.Add(AddressRecord.Create(hostName, addr));
                    }
                }
                return msg.ToByteArray();
            }
            finally
            {
                msg.AdditionalRecords.Clear();
                msg.AdditionalRecords.AddRange(allAdditional);
                msg.Answers.Clear();
                msg.Answers.AddRange(allAnswers);
            }
        }

        void Listen(UdpClient receiver)
        {
            // ReceiveAsync does not support cancellation.  So the receiver is disposed
            // to stop it. See https://github.com/dotnet/corefx/issues/9848
            Task.Run(async () =>
            {
                try
                {
                    var task = receiver.ReceiveAsync();

                    _ = task.ContinueWith(x => Listen(receiver), TaskContinuationOptions.OnlyOnRanToCompletion | TaskContinuationOptions.RunContinuationsAsynchronously);

                    _ = task.ContinueWith(x => MessageReceived?.Invoke(this, x.Result), TaskContinuationOptions.OnlyOnRanToCompletion | TaskContinuationOptions.RunContinuationsAsynchronously);

                    await task.ConfigureAwait(false);
                }
                catch
                {
                    return;
                }
            });
        }

        IEnumerable<IPAddressAndNIC> GetNetworkInterfaceLocalAddresses(NetworkInterface nic)
        {
            return nic
                .GetIPProperties()
                .UnicastAddresses
                .Select(x => new IPAddressAndNIC { Address = x.Address, Interface = nic })
                .Where(x => x.Address.AddressFamily != AddressFamily.InterNetworkV6 || x.Address.IsIPv6LinkLocal)
                ;
        }

        #region IDisposable Support

        private bool disposedValue = false; // To detect redundant calls

        protected virtual void Dispose(bool disposing)
        {
            if (!disposedValue)
            {
                if (disposing)
                {
                    MessageReceived = null;

                    foreach (var receiver in receivers)
                    {
                        try
                        {
                            receiver.Dispose();
                        }
                        catch
                        {
                            // eat it.
                        }
                    }
                    receivers.Clear();
                    senders.Clear();
                }

                disposedValue = true;
            }
        }

        ~MulticastClient()
        {
            Dispose(false);
        }

        // This code added to correctly implement the disposable pattern.
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        #endregion

        private class IPAddressAndNIC
        {
            public IPAddress Address { get; set; }

            public NetworkInterface Interface { get; set; }
        }
    }
}
