# DllVerify

This tool verifies DLL and executable signatures.

Verification is done via the `WinVerifyTrustResult()` in `wintrust.dll`

## Usage

Use `/?` for help.


    DllVerify <FileName> [/V] [/S]

File name can be relative or absolute.

### `/V`

This makes the application output more text.
Most importantly, it prints all search locations when you request help,
and it prints the full DLL file path that was detected if `/S` is used.

### `/S`

This makes the tool search for the DLL file in the same way that Windows would try to find it in a `LoadLibrary()` call.

#### Name modifications

If the name doesn't ends in `.dll`, the extension will be appended.
To prevent this behavior, append a dot to the name.

#### Search locations

The default Windows search order is as follows
*(in order of preference)*:

1. Application path (directory the executable is in)
2. `%SystemRoot%\System32`
3. `%SystemRoot%\System`
4. `%SystemRoot%`
5. Current working directory (`%CD%`)
6. Directories in the path variable (`%PATH%`)

Note:
An application can insert additional locations between 1 and 2.

## Security

This application verifies signatures in the same way Windows would.
This means that it accpets signatures that Windows would also consider as valid.

## Library usage

To use this as a library, simply copy `Verify.cs` into your project.
Then use `Trust.WinTrust.VerifyEmbeddedSignature(DllFileName);`

Searching for DLL files is not part of the application.
You should always feed a full file name and path into the verification function.
