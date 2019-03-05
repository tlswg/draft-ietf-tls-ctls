---
title: Compact TLS 1.3
abbrev: CTLS 1.3
docname: draft-rescorla-tls-ctls-latest
category: info

ipr: trust200902
area: General
workgroup: TODO Working Group
keyword: Internet-Draft

stand_alone: yes
pi: [toc, sortrefs, symrefs]

author:
 -
    ins: E. Rescorla
    name: Eric Rescorla
    organization: Mozilla
    email: ekr@rtfm.com

normative:
  RFC2119:

informative:



--- abstract

This document specifies a "compact" version of TLS 1.3. It is isomorphic
to TLS 1.3 but saves space by aggressive use of defaults and tighter
encodings.


--- middle

# Introduction

This document specifies a "compact" version of TLS 1.3 {{!RFC8446}}. It is isomorphic
to TLS 1.3 but designed to take up minimal bandwidth. The space reduction
is achieved by two basic techniques:

- Default values for common configurations, thus avoiding the need
  to take up space on the wire.

- More compact encodings, omitting unnecessary values.

For the common (EC)DHE handshake with (EC)DHE and pre-established
public keys, CTLS achieves an overhead of XXX bytes over the minimum
required by the cryptovariables.

Although isomorphic, CTLS implementations cannot interoperate with TLS 1.3
implementations because the packet formats are non-interoperable. It is
probably possible to make a TLS 1.3 server switch-hit between CTLS and TLS 1.3
but this specification does not define how.


# Conventions and Definitions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in BCP 14 {{RFC2119}} {{!RFC8174}}
when, and only when, they appear in all capitals, as shown here.

Structure definitions listed below override TLS 1.3 definitions; any PDU
not internally defined is taken from TLS 1.3.

# Common Primitives

## Varints

CTLS makes use of variable-length integers in order to allow a wide
integer range while still providing for a minimal encoding. The
width of the integer is encoded in the first two bits of the field
as follows, with xs indicating bits that form part of the integer.

| Bit pattern | Length (bytes)|
|:-----------|:-------|
| 1xxxxxxx   |1 |
| 10xxxxxx   |2 |
| 11xxxxxx   |3 |

Thus, one byte can be used to carry values up to 127.

In the TLS syntax variable integers are denoted as "varint" and
a vector with a top range of a varint is denoted as:

~~~~~
     opaque foo<1..V>;
~~~~~



## Record Layer

The CTLS Record Layer assumes that records are externally framed
(i.e., that the length is already known). Depending on how this was
carried, you might need another byte or two for that framing. Thus,
only the type byte need be carried. Thus, TLSPlaintext becomes:

~~~~
      struct {
          ContentType type;
          opaque fragment[TLSPlaintext.length];
      } TLSPlaintext;
~~~~

In addition, because the epoch is known in advance, the
dummy content type is not needed for the ciphertext, so
TLSCiphertext becomes:

~~~~
      struct {
          opaque content[TLSPlaintext.length];
          ContentType type;
          uint8 zeros[length_of_padding];
      } TLSInnerPlaintext;

      struct {
          opaque encrypted_record[TLSCiphertext.length];
      } TLSCiphertext;
~~~~

Note: The user is responsible for ensuring that the sequence
numbers/nonces are handled in the usual fashion.

Overhead: 1 byte per record.


## Handshake Layer

The CTLS handshake layer is the same as the TLS 1.3 handshake
layer except that the length is a varint.

~~~~
      struct {
          HandshakeType msg_type;    /* handshake type */
          varint length;             // CHANGED
          select (Handshake.msg_type) {
              case client_hello:          ClientHello;
              case server_hello:          ServerHello;
              case end_of_early_data:     EndOfEarlyData;
              case encrypted_extensions:  EncryptedExtensions;
              case certificate_request:   CertificateRequest;
              case certificate:           Certificate;
              case certificate_verify:    CertificateVerify;
              case finished:              Finished;
              case new_session_ticket:    NewSessionTicket;
              case key_update:            KeyUpdate;
          };
      } Handshake;
~~~~

Overhead: 2 bytes per handshake message (min).

[OPEN ISSUE: This can be shrunk to 1 byte in some cases if we are
willing to use a custom encoding. There are 11 handshake
types, so we can use the first 4 bits for the type and
then the bottom 4 bits for an encoding of the length, but
we would have to offset that by 16 or so to be able to
have a meaningful impact.]]

## Extensions

CTLS Extensions are the same as TLS 1.3 extensions, except varint
length coded:

~~~~
    struct {
        ExtensionType extension_type;
        opaque extension_data<0..V>;
    } Extension;
~~~~


# Handshake Messages

In general, we retain the basic structure of each individual
TLS handshake message. However. The following handshake messages
are slightly modified for space reduction.

## ClientHello

The CTLS ClientHello is as follows.

~~~~
      uint8 ProtocolVersion;
      opaque Random[16];
      uint8 CipherSuite;

      struct {
          ProtocolVersion versions<0..255>;
          Random random;
          CipherSuite cipher_suites<1..V>;
          Extension extensions[remainder_of_message];
      } ClientHello;
~~~~

[[TODO: Define single-byte mappings of the cipher suites and
protocol version.]]

In order to conserve space, the following extensions have default
values which apply if they are not present:

* SignatureAlgorithms: ed25519
* SupportedGroups: the list of groups present in the KeyShare
  extension.
* Pre-Shared Key Exchange Modes: psk_dhe_ke
* Certificate Type: A new TBD value indicating a key index.

As a practical matter, the only extension needed is the KeyShare
extension, as defined below.

Overhead: 8 bytes (min)

* Versions: 1 + No. Versions
* CipherSuites: 1 + No. Suites
* Key shares: 2 + 2 * # shares


### KeyShare

The KeyShare extension is redefined as:


~~~~
      uint8 NamedGroup; // TODO: Need an 8-bit group mapping
      struct {
          NamedGroup group;
          opaque key_exchange<1..V>;
      } KeyShareEntry;

      struct {
          KeyShareEntry client_shares[length of extension];
      } KeyShareClientHello;
~~~~

## ServerHello

We redefine ServerHello in a similar way:

~~~~
      struct {
          ProtocolVersion version;
          Random random;
          CipherSuite cipher_suite;
          Extension extensions[remainder_of_message];
      } ServerHello;
~~~~

The extensions have the same default values as in ClientHello,
so as a practical matter only KeyShare is needed.

Overhead: 6 bytes

* Version: 1
* Cipher Suite: 1
* KeyShare: 4 bytes


### KeyShare
~~~~
      struct {
          KeyShareEntry server_share;
      } KeyShareServerHello;
~~~~

[[OPEN ISSUE: We could save one byte here by removing the length
of the key share and another byte by only allowing the client
to send one key share (so group wasn't needed)..]]


[[TODO: Need to define a single-byte list of NamedGroups]].

## EncryptedExtensions

This is unchanged.

[[OPEN ISSUE: We could save 2 bytes in handshake header by
omitting this value when it's unneeded.]]

## CertificateRequest

This message removes the certificate_request_context and
reeencodes the extensions.

~~~~
      struct {
          Extension extensions[remainder of message];
      } CertificateRequest;
~~~~



## Certificate

Certificate is essentially unchanged for the X.509-based modes
but as an exception when you negotiate the KeyID-based mode,
we redefine Certificate as:

~~~~
    struct {
        varint key_id;
    } KeyIdCertificate;
~~~~


### CertificateVerify

Unchanged.


### Finished

Unchanged.



# Handshake Size Calculations

## ECDHE w/ Signatures

We compute the total flight size with X25519 and P-256 signatures,
thus the keys are 32-bytes long and the signatures 64 bytes,
with a cipher with an 8 byte auth tag. Overhead estimates marked
with *** have been verified with Mint.


### Flight 1 (ClientHello) ***

* Random: 16
* KeyShare: 32
* Message Overhead: 8
* Handshake Overhead: 2
* Record Overhead: 1
* Total: 59


### Flight 2 (ServerHello..Finished)

ServerHello ***

* Random: 16
* KeyShare: 32
* Message Overhead: 6
* Handshake Overhead: 2
* Record Overhead: 1
* Total: 57

EncryptedExtensions ***

* Total: 2

CertificateRequest ***

* Total: 2

Certificate ***

* KeyId: 1
* Overhead: 2
* Total: 3

CertificateVerify

* Signature: 64
* Overhead: 2
* Total: 66

Finished

* MAC: 32
* Overhead: 2
* Total: 43


Handshake Overhead: 12 bytes (6 messages)
Record Overhead: 2 bytes (2 records) + 8 bytes (auth tag).

[[OPEN ISSUE: We'll actually need a length field for the ClientHello,
so add 1 here]]


Total Size: 188 bytes.


### Flight 3 (Client Certificate..Finished)

Certificate

* KeyId: 1
* Overhead: 2
* Total: 3

CertificateVerify

* Signature: 64
* Overhead: 2
* Total: 66

Finished

* MAC: 32
* Overhead: 2
* Total: 43


Handshake Overhead: 6 bytes (3 messages)
Record Overhead: 1 byte + 8 bytes (auth tag)

Total: 127.


## ECDHE w/ PSK

[TODO]



# Security Considerations

CTLS is isomorphic to TLS 1.3, and therefore should have the
same security considerations. [[OPEN ISSUE: One could imagine
internally translating CTLS to TLS 1.3 so that the transcript,
etc. were the same, but I doubt it's worth it, and then you
might need to worry about cross-protocol attacks.]]


# IANA Considerations

This document has no IANA actions.



--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
