# Azure VPN group-token interoperability

The official Windows client 4.0.5.0 supplies two credentials when the profile
sets `enablegrouptoken`: the gateway-audience token and a Microsoft Graph token.
Requesting a `groups` claim on the gateway token is not the same exchange.

Wire format (ASCII, no separators or terminating NUL inside the credential):

```
TlvToken:00<vpn length as 8 lowercase hex digits><vpn token>01<graph length as 8 lowercase hex digits><graph token>
```

Types are two ASCII characters. Lengths count token characters, which equal
bytes for the accepted bearer-token alphabet. OpenVPN adds its own framing.
Graph scope is `https://graph.microsoft.com/.default`. The gateway evaluates
membership: the client neither chooses a network group nor invents claims.

## Evidence

Inspected the Windows client from Microsoft's download page:
https://www.microsoft.com/en-us/download/details.aspx?id=108598

In `AzVpnAppx.exe`, the credential assembly at VA `0x14027cb3f`–`0x14027cc71`
concatenates `TlvToken:`, `00`, `%08x` of the first token length, the first token,
`01`, `%08x` of the second token length, and the second token. Constants are at
VA `0x140325398`, `0x14031a12c`, `0x14031a134`, and `0x14031a140` respectively.
No official client executable was run or installed.

The combined VPN and Graph credential can exceed the previous 4096-byte limit.
The two-constant OpenVPN patch now allows 8192 credential bytes, including its
NUL terminator, and 16384 bytes for the TLS control-channel buffer. Existing
BUILDINFO-based limits still reject oversized credentials before transmission.
Unknown binaries retain the conservative 4096-byte assumed limit.

## Limits

Only Azure Public has been tested. Graph consent must already be available
for the same application. This build fails closed if silent Graph acquisition
fails or returns another account/tenant, rather than opening an account picker
that could select a different identity. No fallback to a VPN-only credential
is allowed for profiles that require group authentication.
