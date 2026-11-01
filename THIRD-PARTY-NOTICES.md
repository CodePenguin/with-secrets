# Third-party notices

`with-secrets.exe` is a self-contained build. It contains the components below. Each is used under its own license, which is reproduced here as that license requires. The `with-secrets` code itself is under the license in `LICENSE`.

## Dotenvx for .NET

Packages: `Dotenvx.Core`, `Dotenvx.Primitives`, `Dotenvx.Providers` (https://github.com/CodePenguin/dotnet-dotenvx), a .NET port of dotenvx (https://github.com/dotenvx/dotenvx). License: BSD-3-Clause.

```
BSD 3-Clause License

Copyright (c) 2024, Scott Motte
Copyright (c) 2026, David Lambert (.NET port)

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its
   contributors may be used to endorse or promote products derived from
   this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```

## Bouncy Castle

Package: `BouncyCastle.Cryptography` 2.6.2 (https://www.bouncycastle.org/). License: MIT.

```
Copyright (c) 2000-2025 The Legion of the Bouncy Castle Inc. (https://www.bouncycastle.org).
Permission is hereby granted, free of charge, to any person obtaining a copy of this software and
associated documentation files (the "Software"), to deal in the Software without restriction,
including without limitation the rights to use, copy, modify, merge, publish, distribute,
sub license, and/or sell copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions: The above copyright notice and this
permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT
NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT
OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
```

## Microsoft and .NET components

- `System.CommandLine` 2.0.0 (https://github.com/dotnet/command-line-api)
- `Microsoft.Extensions.Configuration`, `Configuration.Abstractions`, `DependencyInjection.Abstractions`, `FileSystemGlobbing`, `Logging.Abstractions`, `Primitives` 10.0.0 (https://github.com/dotnet/runtime)
- The .NET runtime and base class libraries (https://github.com/dotnet/runtime)

License: MIT. The runtime also carries notices for the third-party code inside it: https://github.com/dotnet/runtime/blob/main/THIRD-PARTY-NOTICES.TXT

```
The MIT License (MIT)

Copyright (c) .NET Foundation and Contributors
Copyright (c) Microsoft Corporation

All rights reserved.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## Windows SDK .NET projection

The approval window and the Windows Hello prompt use the Windows Runtime through the .NET projection from the `Microsoft.Windows.SDK.NET.Ref` package (10.0.19041.57), which is part of the exe. It is not under the MIT license. Its terms are the Microsoft Windows SDK license terms: https://aka.ms/WinSDKLicenseURL (Copyright (c) Microsoft Corporation). The terms are not reproduced here.
