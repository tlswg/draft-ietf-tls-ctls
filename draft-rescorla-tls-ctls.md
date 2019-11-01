---
title: Compact TLS 1.3
abbrev: CTLS 1.3
docname: draft-rescorla-tls-ctls-latest
category: info

ipr: trust200902
area: General
workgroup: TLS Working Group
keyword: Internet-Draft

stand_alone: yes
pi: [toc, sortrefs, symrefs]

author:
 -
    ins: E. Rescorla
    name: Eric Rescorla
    organization: Mozilla
    email: ekr@rtfm.com

 -
    ins: R. Barnes
    name: Richard Barnes
    organization: Cisco
    email: rlb@ipv.sx

normative:
  RFC2119:

informative:



--- abstract

This document specifies a "compact" version of TLS 1.3. It is
isomorphic to TLS 1.3 but saves space by trimming obsolete material,
tighter encoding, and a template-based specialization technique. CTLS
is not interoperable with TLS 1.3, but it should eventually be
possible for the server to distinguish TLS 1.3 and CTLS handshakes.


--- middle

# Introduction

DISCLAIMER: This is a work-in-progress draft of cTLS and has not yet
seen significant security analysis, so could contain major errors. It
should not be used as a basis for building production systems.

This document specifies a "compact" version of TLS 1.3 {{!RFC8446}}. It is isomorphic
to TLS 1.3 but designed to take up minimal bandwidth. The space reduction
is achieved by three basic techniques:

- Omitting unnecessary values that are a holdover from previous versions
  of TLS.
- More compact encodings, omitting unnecessary values.
- A template-based specialization mechanism that allows for the creation
  of application specific versions of TLS that omit unnecessary
  valuses.

For the common (EC)DHE handshake with (EC)DHE and pre-established
public keys, CTLS achieves an overhead of [TODO] bytes over the minimum
required by the cryptovariables.

Because cTLS is semantically equivalent to TLS, it can be viewed either
as a related protocol or as a compression mechanism. Specifically, it
can be implemented by a layer between the TLS handshake state
machine and the record layer.

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


| Bit pattern                | Length (bytes) |
|:----------------------------|:----------------|
| 0xxxxxxx                   | 1              |
|                            |                |
| 10xxxxxx xxxxxxxx          | 2              |
|                            |                |
| 11xxxxxx xxxxxxxx xxxxxxxx | 3              |

Thus, one byte can be used to carry values up to 127.

In the TLS syntax variable integers are denoted as "varint" and
a vector with a top range of a varint is denoted as:

~~~~~
     opaque foo<1..V>;
~~~~~

With a few exceptions, CTLS replaces every integer in TLS
with a varint.

[[OPEN ISSUE: Should we just re-encode this directly in CBOR?.
That might be easier for people, but I ran out of time.]]

## Record Layer

The CTLS Record Layer assumes that records are externally framed
(i.e., that the length is already known because it is carried in a UDP
datagram or the like). Depending on how this was carried, you might
need another byte or two for that framing. Thus, only the type byte
need be carried and TLSPlaintext becomes:

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
TLS handshake message. However, the following handshake
messages have been modified for space reduction and cleaned
up to remove pre TLS 1.3 baggage.

## ClientHello

The CTLS ClientHello is as follows.

~~~~
      uint8 ProtocolVersion;            // 1 byte
      opaque Random[RandomLength];      // variable length
      uint8 CipherSuite;                // 1 byte

      struct {
          ProtocolVersion versions<0..255>;
          Random random;
          CipherSuite cipher_suites<1..V>;
          Extension extensions[remainder_of_message];
      } ClientHello;
~~~~

[[TODO: Define single-byte mappings of the cipher suites and
protocol version.]]

The versions list from "supported_versions" has moved into
ClientHello.versions with versions being one byte, but with the modern
semantics of the client offering N versions and the server picking
one.


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


### PreSharedKeys

[[TODO]]


## EncryptedExtensions

Unchanged.

[[OPEN ISSUE: We could save 2 bytes in handshake header by
omitting this value when it's unneeded.]]

## CertificateRequest

This message removes the certificate_request_context and
re-encodes the extensions.

~~~~
      struct {
          Extension extensions[remainder of message];
      } CertificateRequest;
~~~~



## Certificate

We can slim down the Certficate message somewhat.

~~~~
      enum {
          X509(0),
          RawPublicKey(2),
          (255)
      } CertificateType;

      struct {
          select (certificate_type) {
              case RawPublicKey:
                /* From RFC 7250 ASN.1_subjectPublicKeyInfo */
                opaque ASN1_subjectPublicKeyInfo<1..V>;

              case X509:
                opaque cert_data<1..V>;
          };
          Extension extensions<0..V>;
      } CertificateEntry;

      struct {
          CertificateEntry certificate_list[rest of extension];
      } Certificate;
~~~~

For a single certificate, this message will have a minumum of 2 bytes of
overhead for the two length bytes.

[[OPEN ISSUE: What should the default type be?]]

### CertificateVerify

We remove the signature algorithm and assume it's tied to the
key. Note that this does not work for RSA keys, but if
we just decide to be EC only, it works fine.

[[OPEN ISSUE: This may be too much.]]

~~~~
      struct {
          opaque signature[rest of message];
      } CertificateVerify;
~~~~

### Finished

Unchanged.

### HelloRetryRequest

[[TODO]]


# Template-Based Specialization





# Security Considerations

WARNING: This document is effectively brand new and has seen no
analysis. The idea here is that CTLS is isomorphic to TLS 1.3, and
therefore should provide equivalent security guarantees, modulo use of
new features such as KeyID certificate messages.


One piece that is a new TLS 1.3 feature is the addition of the key_id,
which definitely requires some analysis, especially as it looks like
a potential source of identity misbinding. This is entirely separable
from the rest of the specification. The compression version would also
need further analysis.


# IANA Considerations

This document has no IANA actions.



--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
