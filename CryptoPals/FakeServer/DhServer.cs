using System;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace CryptoPals
{
    public class DhServer
    {
        public static int IdCounter = 0;

        public int Id { get; private set; }
        private KeyPair _keyPair;
        private Dictionary<int, ServerInfo> _serverInfoDict;

        public DhServer() {
            Id = IdCounter++;
            _keyPair = DiffieHelman.GenerateKeypair();
            _serverInfoDict = new Dictionary<int, ServerInfo>();
        }

        private byte[] generateKey(DhServer other) {
            var info = _serverInfoDict[other.Id];
            byte[] sessionKey = DiffieHelman.GenerateSessionKey(info.PublicKey, _keyPair.PrivateKey);
            return ByteArrayHelpers.CopyPartOf(Sha1.Hash(sessionKey), 0, 16);
        }

        // Setup connection
        public virtual DhInitiation InitiateDh(DhServer receiver) {
            var randomPrime = DiffieHelman.P; // Much unexpected. Such random. Wow.
            return new DhInitiation(this, receiver, randomPrime, DiffieHelman.G, _keyPair.PublicKey);
        }

        public virtual DhInitiationResponse ReceiveInitiationRequest(DhInitiation request) {
            _serverInfoDict.Add(request.From.Id, new ServerInfo(request.From.Id, request.P, request.G, request.PublicKey));
            return SendPublicKey(request.From, _keyPair.PublicKey);
        }

        public virtual DhInitiationResponse SendPublicKey(DhServer receiver, byte[] publicKey) {
            return new DhInitiationResponse(this, receiver, publicKey);
        }

        public virtual void ReceiveInitiationResponse(DhInitiationResponse request) {
            _serverInfoDict.Add(request.From.Id, new ServerInfo(request.From.Id, DiffieHelman.P, DiffieHelman.G, request.PublicKey));
        }

        // Setup connection with negotiated groups
        public virtual DhNegotiation InitiateDhNegotiation(DhServer receiver) {
            var randomPrime = DiffieHelman.P; // Much unexpected. Such random. Wow.
            return new DhNegotiation(this, receiver, randomPrime, DiffieHelman.G);
        }

        public virtual DhNegotiation ReceiveDhNegotiationRequest(DhNegotiation request) {
            _serverInfoDict.Add(request.From.Id, new ServerInfo(request.From.Id, request.P, request.G, null));
            return new DhNegotiation(this, request.From, request.P, request.G);
        }

        public virtual DhInitiationResponse ReceiveDhNegotiationResponse(DhNegotiation request) {
            _keyPair = DiffieHelman.GenerateKeypair(request.P, request.G);
            _serverInfoDict.Add(request.From.Id, new ServerInfo(request.From.Id, DiffieHelman.P, DiffieHelman.G, null));
            return new DhInitiationResponse(this, request.From, _keyPair.PublicKey);
        }

        public virtual DhInitiationResponse ReceiveDhNegotiatedPublicKey(DhInitiationResponse request) {
            var info = _serverInfoDict[request.From.Id];
            info.PublicKey = request.PublicKey;
            _serverInfoDict[request.From.Id] = info;
            _keyPair = DiffieHelman.GenerateKeypair(info.P, info.G);
            return new DhInitiationResponse(this, request.From, _keyPair.PublicKey);
        }

        public virtual void ReceiveDhFinalNegotiatedPublicKey(DhInitiationResponse request) {
            var info = _serverInfoDict[request.From.Id];
            info.PublicKey = request.PublicKey;
            _serverInfoDict[request.From.Id] = info;
        }

        // Send messages
        public virtual DhMessage SendTextMessage(DhServer receiver, string message) {
            return SendMessage(receiver, ConversionHelpers.FromUTF8String(message));
        }
        public virtual DhMessage SendMessage(DhServer receiver, byte[] message) {
            byte[] key = generateKey(receiver);
            byte[] iv = RandomHelpers.RandomByteArray(16);
            byte[] cypher = BlockCipher.EncryptAES(message, key, iv, CipherMode.CBC, PaddingMode.PKCS7);
            var result = BlockCipher.Result(cypher, iv);

            return new DhMessage(this, receiver, result);
        }

        public virtual byte[] ReceiveMessage(DhMessage request) {
            byte[] key = generateKey(request.From);
            return BlockCipher.DecryptAES(request.Message.Cipher, key, request.Message.Iv, CipherMode.CBC, PaddingMode.PKCS7);
        }
        public virtual string ReceiveTextMessage(DhMessage request) {
            byte[] plain = ReceiveMessage(request);
            return ConversionHelpers.ToUTF8String(plain);
        }
    }

    public struct ServerInfo
    {
        public int ServerId;
        public byte[] P, G, PublicKey;

        public ServerInfo(int serverId, byte[] p, byte[] g, byte[] publicKey) {
            ServerId = serverId;
            P = p;
            G = g;
            PublicKey = publicKey;
        }
    }

    public struct DhInitiation
    {
        // Apparently, DH has forward secrecy, but I don't see how that works.
        // Eve can see the chosen P and G, if she also knows all public keys and one of the private keys, then she has everything she needs to decrypt all recorded traffic right?
        public DhServer From, To;
        public byte[] P, G, PublicKey;

        public DhInitiation(DhServer from, DhServer to, byte[] p, byte[] g, byte[] publicKey) {
            From = from;
            To = to;
            P = p;
            G = g;
            PublicKey = publicKey;
        }

        public void Deconstruct(out byte[] p, out byte[] g, out byte[] publicKey) {
            p = P;
            g = G;
            publicKey = PublicKey;
        }
    }

    public struct DhInitiationResponse
    {
        public DhServer From, To;
        public byte[] PublicKey;

        public DhInitiationResponse(DhServer from, DhServer to, byte[] publicKey) {
            From = from;
            To = to;
            PublicKey = publicKey;
        }
    }

    public struct DhNegotiation
    {
        public DhServer From, To;
        public byte[] P, G;

        public DhNegotiation(DhServer from, DhServer to, byte[] p, byte[] g) {
            From = from;
            To = to;
            P = p;
            G = g;
        }

        public void Deconstruct(out byte[] p, out byte[] g) {
            p = P;
            g = G;
        }
    }

    public struct DhMessage
    {
        public DhServer From, To;
        public BlockCipherResult Message;

        public DhMessage(DhServer from, DhServer to, BlockCipherResult message) {
            From = from;
            To = to;
            Message = message;
        }
    }
}
