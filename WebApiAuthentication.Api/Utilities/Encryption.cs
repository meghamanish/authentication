// <copyright file="Encryption.cs" company="CoStar Group, Inc.">All rights reserved.</copyright>

using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Security.Cryptography;
using System.Text;

namespace WebApiAuthentication.Api.Utilities;

internal class Encryption : IEncryption
{
    private string EncryptionKey { get; }

    public Encryption(IConfiguration configuration)
    {
        EncryptionKey = configuration["Encryption:EncryptionKey"];
    }

    public string? EncryptId(int? id)
    {
        if (id == null)
        {
            return null;
        }

        using Aes aes = Aes.Create();
        var keyBytes = Encoding.ASCII.GetBytes(this.EncryptionKey);
        aes.Key = keyBytes;
        aes.GenerateIV();

        var encryptedBytes = aes.EncryptCbc(BitConverter.GetBytes(id.Value), aes.IV, PaddingMode.PKCS7);

        var combinedBytes = new byte[aes.IV.Length + encryptedBytes.Length];
        Buffer.BlockCopy(aes.IV, 0, combinedBytes, 0, aes.IV.Length);
        Buffer.BlockCopy(encryptedBytes, 0, combinedBytes, aes.IV.Length, encryptedBytes.Length);

        var str = Microsoft.AspNetCore.WebUtilities.WebEncoders.Base64UrlEncode(combinedBytes);
        return str;
    }

    public int DecryptId(string encoded)
    {
        using Aes aes = Aes.Create();
        var keyBytes = Encoding.ASCII.GetBytes(this.EncryptionKey);
        aes.Key = keyBytes;

        var bytes = Microsoft.AspNetCore.WebUtilities.WebEncoders.Base64UrlDecode(encoded);
        var iv = new byte[aes.IV.Length];
        Buffer.BlockCopy(bytes, 0, iv, 0, iv.Length);
        var encBytes = new byte[bytes.Length - iv.Length];
        Buffer.BlockCopy(bytes, iv.Length, encBytes, 0, bytes.Length - iv.Length);

        var decBytes = aes.DecryptCbc(encBytes, iv, PaddingMode.PKCS7);
        var n = BitConverter.ToInt32(decBytes, 0);
        return n;
    }

    public string GetHash(string input)
    {
        using SHA256 sha256 = SHA256.Create();

        byte[] inputBytes = Encoding.UTF8.GetBytes(input);
        byte[] hashBytes = sha256.ComputeHash(inputBytes);

        var s = System.Convert.ToBase64String(hashBytes);

        return s;
    }
}