namespace WithSecrets;

/// <summary>A review public key and the corresponding private key wrapped under the master key.</summary>
public sealed record ReviewKey(string PublicKey, string Vault);
