# Azure VPN group-token interoperability

The official Windows client supplies two credentials when the profile sets
`enablegrouptoken` to `true`: the gateway-audience token and a Microsoft Graph
token. Requesting a `groups` claim on the gateway token is not the same exchange.

Wire format (ASCII, no separators or terminating NUL inside the credential):

```
TlvToken:00<vpn length as 8 lowercase hex digits><vpn token>01<graph length as 8 lowercase hex digits><graph token>
```

Types are two ASCII characters. Lengths count token characters, which equal
bytes for the accepted bearer-token alphabet. OpenVPN adds its own framing. The
client neither chooses a network group nor invents claims.

## Evidence

This comes from static inspection of Windows client 4.0.5.0, from Microsoft's
download page: https://www.microsoft.com/en-us/download/details.aspx?id=108598

The inspection confirmed the format above, that the VPN token is type `00` and
the Graph token type `01`, and that the client sends both only when the setting
is exactly `true`. No official client executable was run or installed.

How the gateway uses the second token cannot be established from the client,
and this has not yet been confirmed against a live gateway.

## Where OpenP2S differs from the client

- **Graph request.** The client asks the Windows token broker for the Graph
  resource with an empty scope. MSAL has no such form, so OpenP2S requests
  `https://graph.microsoft.com/.default`. Whether the two give an equivalent
  token has not been confirmed.
- **Username.** The client sends the account's user name, and OpenP2S sends
  `AzureAD`, as it does for every profile.
- **Validation.** OpenP2S refuses to send a token outside the bearer-token
  alphabet, or a Graph token for another account or tenant. The client checks
  neither.

## When no Graph token is available

Like the client, OpenP2S only requests the Graph token silently, because a prompt
could select a different identity. If it cannot get one, it connects with the VPN
token alone, which is also what the client does, and the gateway may then assign
its default address pool. OpenP2S warns when this happens.

A reconnect is stricter. A live session keeps the account and the kind of
credential it started with, because a change could move the user to another
address pool with nobody watching. If it can't, OpenVPN stops and the user is asked
to connect again. The client falls back here too, so this is a deliberate
difference.

A Graph token is only sent to a gateway whose certificate name is checked; see
[SECURITY.md](SECURITY.md).

## Credential size

The combined VPN and Graph credential can exceed the previous 4096-byte limit.
The two-constant OpenVPN patch now allows 8192 credential bytes, including its
NUL terminator, and 16384 bytes for the TLS control-channel buffer. Limits read
from BUILDINFO still reject oversized credentials before transmission. A binary
whose BUILDINFO records no limit is assumed to have 4096 bytes, and one with no
trusted BUILDINFO is assumed to have 128. The gateway's own limit is not known.

## Limits

Group authentication supports Azure Public only, and Graph consent must already
be available for the same application.
