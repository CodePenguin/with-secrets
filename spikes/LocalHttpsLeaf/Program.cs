using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Server.Kestrel.Core;

const string host = "with-secrets.localhost";
var dir = Path.Combine(Path.GetTempPath(), "with-secrets-leaf-" + Guid.NewGuid().ToString("N"));
Directory.CreateDirectory(dir);
using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
var req = new CertificateRequest("CN=" + host, key, HashAlgorithmName.SHA256);
var san = new SubjectAlternativeNameBuilder();
san.AddDnsName(host);
req.CertificateExtensions.Add(san.Build());
req.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
req.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
req.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new Oid("1.3.6.1.5.5.7.3.1") }, true));
using var leaf = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddYears(10));
using var childKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
var childReq = new CertificateRequest("CN=localhost", childKey, HashAlgorithmName.SHA256);
var childSan = new SubjectAlternativeNameBuilder();
childSan.AddDnsName("localhost");
childReq.CertificateExtensions.Add(childSan.Build());
childReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
childReq.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
childReq.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new Oid("1.3.6.1.5.5.7.3.1") }, true));
using var childPublic = childReq.Create(leaf.SubjectName, X509SignatureGenerator.CreateForECDsa(key), DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddDays(1), RandomNumberGenerator.GetBytes(16));
using var child = childPublic.CopyWithPrivateKey(childKey);
// Schannel requires persisted key material; use temporary user key storage for this spike only.
using var server = OperatingSystem.IsWindows() ? X509CertificateLoader.LoadPkcs12(leaf.Export(X509ContentType.Pfx), null, X509KeyStorageFlags.UserKeySet) : new X509Certificate2(leaf);
using var negative = OperatingSystem.IsWindows() ? X509CertificateLoader.LoadPkcs12(child.Export(X509ContentType.Pfx), null, X509KeyStorageFlags.UserKeySet) : new X509Certificate2(child);
var path = Path.Combine(dir, "leaf.cer");
File.WriteAllBytes(path, leaf.Export(X509ContentType.Cert));
Console.WriteLine($"Public certificate: {path}\nSHA256: {leaf.GetCertHashString(HashAlgorithmName.SHA256)}\nSHA1 (cleanup): {leaf.Thumbprint}");
var builder = WebApplication.CreateBuilder(args);
builder.WebHost.ConfigureKestrel(k => {
    k.ListenLocalhost(18765, l => l.UseHttps(server));
    k.ListenLocalhost(18766, l => l.UseHttps(negative));
});
var app = builder.Build();
app.MapGet("/", () => Results.Content("""
<!doctype html><meta charset="utf-8"><title>Local TLS spike</title>
<h1>Local TLS spike</h1><p id="status"></p>
<button id="register">Register disposable passkey</button>
<button id="auth">Authenticate</button><pre id="result"></pre>
<script>
const rpId='with-secrets.localhost', random=()=>crypto.getRandomValues(new Uint8Array(32));
let id;
statusEl=document.getElementById('status');
statusEl.textContent=location.origin+' secureContext='+isSecureContext;
const out=document.getElementById('result');
document.getElementById('register').onclick=async()=>{try{
const c=await navigator.credentials.create({publicKey:{rp:{id:rpId,name:'with-secrets TLS spike'},user:{id:random(),name:'spike-'+Date.now(),displayName:'Disposable TLS spike'},challenge:random(),pubKeyCredParams:[{type:'public-key',alg:-7},{type:'public-key',alg:-257}],authenticatorSelection:{userVerification:'required'},timeout:60000}});
id=c.rawId;out.textContent='Registration returned credential';
}catch(e){out.textContent=e.name+': '+e.message}};
document.getElementById('auth').onclick=async()=>{try{
if(!id)throw Error('Register first');
await navigator.credentials.get({publicKey:{rpId,challenge:random(),allowCredentials:[{type:'public-key',id}],userVerification:'required',timeout:60000}});
out.textContent='Authentication returned assertion (not server-verified)';
}catch(e){out.textContent=e.name+': '+e.message}};
</script>
""", "text/html"));
try { await app.RunAsync(); } finally { Directory.Delete(dir, true); }
