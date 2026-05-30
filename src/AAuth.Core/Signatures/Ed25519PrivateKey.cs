using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace AAuth.Core.Signatures;

/// <summary>
/// Ed25519 private signing key material for HTTP Message Signatures.
/// </summary>
public sealed class Ed25519PrivateKey : AsymmetricAlgorithm
{
    private const int PrivateKeySize = 32;
    private readonly byte[] _privateKeyBytes;

    private Ed25519PrivateKey(byte[] privateKeyBytes)
    {
        _privateKeyBytes = privateKeyBytes;
    }

    /// <summary>
    /// Generate a new Ed25519 private key.
    /// </summary>
    public static Ed25519PrivateKey Generate()
    {
        var key = new Ed25519PrivateKeyParameters(new SecureRandom());
        return new Ed25519PrivateKey(key.GetEncoded());
    }

    /// <summary>
    /// Create an Ed25519 private key from 32-byte private key material.
    /// </summary>
    public static Ed25519PrivateKey FromPrivateKeyBytes(byte[] privateKeyBytes)
    {
        if (privateKeyBytes.Length != PrivateKeySize)
            throw new FormatException($"Ed25519 private key must be {PrivateKeySize} bytes.");

        return new Ed25519PrivateKey([.. privateKeyBytes]);
    }

    /// <summary>
    /// Export the private key bytes.
    /// </summary>
    public byte[] ExportPrivateKeyBytes() => [.. _privateKeyBytes];

    /// <summary>
    /// Export the corresponding public key as an Ed25519 JWK.
    /// </summary>
    public JsonWebKey ExportPublicJwk()
    {
        var publicKey = ToPrivateKeyParameters().GeneratePublicKey();
        return new JsonWebKey
        {
            Kty = "OKP",
            Crv = "Ed25519",
            Alg = "EdDSA",
            X = Base64UrlEncoder.Encode(publicKey.GetEncoded())
        };
    }

    /// <inheritdoc />
    public override string? KeyExchangeAlgorithm => null;

    /// <inheritdoc />
    public override string SignatureAlgorithm => "EdDSA";

    internal Ed25519PrivateKeyParameters ToPrivateKeyParameters() => new(_privateKeyBytes, 0);
}
