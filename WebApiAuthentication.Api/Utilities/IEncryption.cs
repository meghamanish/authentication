// <copyright file="IEncryption.cs" company="CoStar Group, Inc.">All rights reserved.</copyright>

namespace WebApiAuthentication.Api.Utilities;
internal interface IEncryption
{
    public string? EncryptId(int? id);

    public int DecryptId(string encoded);

    public string GetHash(string input);
}
