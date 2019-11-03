---
title: Compact TLS 1.3
abbrev: cTLS 1.3
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
tighter encoding, and a template-based specialization technique. cTLS
is not interoperable with TLS 1.3, but it should eventually be
possible for the server to distinguish TLS 1.3 and cTLS handshakes.


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
public keys, cTLS achieves an overhead of [TODO] bytes over the minimum
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
not internally defined is taken from TLS 1.3 except for replacing integers
with varints.

# Common Primitives

## Varints

cTLS makes use of variable-length integers in order to allow a wide
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

With a few exceptions, cTLS replaces every integer in TLS
with a varint.


## Record Layer

The cTLS Record Layer assumes that records are externally framed
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

The cTLS handshake layer is the same as the TLS 1.3 handshake
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

cTLS Extensions are the same as TLS 1.3 extensions, except varint
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

The cTLS ClientHello is as follows.

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

The mapping for TLS 1.3 ciphersuites to their 1 byte equivalent is 
defined as the low-order byte of the existing TLS 1.3 IANA 
ciphersuite registry values. 

+------------------------------+-------------+--------+
| Ciphersuite                  | TLS 1.3 IANA| cTLS   |
|                              |   Value     |Mapping |
+------------------------------+-------------+--------+
| TLS_AES_128_GCM_SHA256       | {0x13,0x01} | 0x01   |
|                              |             |        |
| TLS_AES_256_GCM_SHA384       | {0x13,0x02} | 0x02   |
|                              |             |        |
| TLS_CHACHA20_POLY1305_SHA256 | {0x13,0x03} | 0x03   |
|                              |             |        |
| TLS_AES_128_CCM_SHA256       | {0x13,0x04} | 0x04   |
|                              |             |        |
| TLS_AES_128_CCM_8_SHA256     | {0x13,0x05} | 0x05   |
+------------------------------+-------------+--------+             

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

In cTLS the client only provides a single key share to the server, 
which represents reduced functionality compared to TLS 1.3 where the 
client can send a number of key shares. 

The KeyShareClientHello extension is defined as follows:

~~~~
      struct {
          KeyShareEntry client_shares;
      } KeyShareClientHello;
~~~~

The KeyShareServerHello extension is defined as follows:

~~~~
      struct {
          KeyShareEntry server_share;
      } KeyShareServerHello;
~~~~

This specification defines a mapping of the named groups
defined in TLS 1.3. An extra column in the IANA mantained 
TLS Supported Groups registry provides this information. 

+------------------------------+-------------+--------+
| Elliptic Curve Groups (ECDHE)| Current IANA| cTLS   |
|                              |   Value     |Mapping |
+------------------------------+-------------+--------+
| secp256r1                    | 0x0017      | 0x01   |
|                              |             |        |
| secp384r1                    | 0x0018      | 0x02   |
|                              |             |        |
| secp521r1                    | 0x0019      | 0x03   |
|                              |             |        |
| x25519                       | 0x001D      | 0x04   |
|                              |             |        |
| x448                         | 0x001E      | 0x05   |
+------------------------------+-------------+--------+

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

This just removes the length field.
~~~~
      struct {
          SignatureScheme algorithm; // TODO -- define one byte schemes.
          opaque signature[rest of message];
      } CertificateVerify;
~~~~

### Finished

Unchanged.

### HelloRetryRequest

[[TODO]]


# Template-Based Specialization

The protocol in the previous section is fully general and isomorphic
to TLS 1.3; effectively it's just a small cleanup of the wire encoding
to match what we might have done starting from scratch. It achieves
some compaction, but only a modest amount. cTLS also includes a mechanism
for achieving very high compaction using template-based specialization.

The basic idea is that we start with the basic TLS 1.3 handshake,
which is fully general and then remove degrees of freedom, eliding
parts of the handshake which are used to express those degrees of
freedom. For example, if we only support one version of TLS, then it
is not necessary to have version negotiation and the
ClientHello.version and ServerHello.version fields can be omitted.
Importantly, this process is performed only for the wire encoding but
not for the handshake transcript.  The result is that the cTLS
handshake transcript is the same as the corresponding TLS 1.3
handshake transcript. [[OPEN ISSUE: Except possibly inserting sme
extension indicating the use of cTLS.]]

One way of thinking of this is as if specialization
is a layer between the handshake and the record layer:

~~~~~
+---------------+---------------+---------------+
|   Handshake   |  Application  |     Alert     |
+---------------+---------------+---------------+
|               cTLS Compression Layer          |
+---------------+---------------+---------------+
|               cTLS Record Layer               |
+---------------+---------------+---------------+
~~~~~

## Specifying a Specialization

A specific instantiation of a specialized version of TLS is
defined using a JSON dictionary. Each axis of specialization
is a key in the dictionary. [[OPEN ISSUE: If we ever want to
serialize this, we'll want to use a list instead.]].

For example, the following specialization describes a protocol
with a single fixed version (TLS 1.3) and a single fixed
cipher suite (TLS_AES_128_GCM_SHA256). On the wire,
ClientHello.versions, ClientHello.cipher_suites,
ServerHello.version, and ServerHello.cipher_suites would
be omitted.

~~~~
{
   "Version" : 772,
   "CipherSuite" : "TLS_AES_128_GCM_SHA256"
}
~~~~

cTLS allows specialization along the following axes:

Version (integer):
: indicates that both sides agree to the
single TLS version specified by the given integer value
(772 == 0x0304 for TLS 1.3). The ClientHello.versions
field field is omitted and reconstructed in the transcript
as a single-valued list with the specified value. The ServerHello.version field is
omitted and reconstructed in the transcript as the specified value.

CipherSuite (string):
: indicates that both sides agree to
the single named cipher suite, using the "TLS_AEAD_HASH" syntax
defined in {{RFC8446}}, section 8.4. The ClientHello.cipher_suites
field is omitted and reconstructed in the transcript as a single-valued
list with the specified value. The server_hello.cipher_suite field is
omitted and reconstructed in the transcript as the specified value.

Random (integer):
: indicates that the ClientHello.Random and ServerHello.Random values
are truncated to the given values. When the transcript is
reconstructed, the Random is padded to the right with 0s and the
anti-downgrade mechanism in {{RFC8446)}, section 4.1.3 is disabled.
IMPORTANT: Using short Random values can lead to potential
attacks. When Random values are shorter than 8 bytes, PSK-only modes
MUST NOT be used, and each side MUST use fresh DH ephemerals.
The Random length MUST be less than or equal to 32 bytes.

Finished (integer):
: indicates that the Finished value is to be truncated to the given
length. When the transcript is reconstructed, the remainder of the
Finished value is filled in by the receiving side.
[[OPEN ISSUE: How short should we allow this to be?]]


Extensions (dictionary):
: a set of extensions which are being specialized, with each one
having its own dictionary entry. The keys in the dictionary entries
are the extension names specified in the TLS ExtensionTypeRegistry
specified in {{RFC8446}}.  Each extension type may have either a
string value indicating the value of the extension in hex or the value
null indicating that the extension will be present but serialized as
described below. If the special extension name "..." is not present,
then the list of extensions is exhaustive. If present, the extension
"..." MUST have the value null.

DHGroup (string):
: specifies a single DH group to use for key establishment. The
group is listed by the code point name in {{RFC8446}}, Section 4.2.7.
(e.g., x25519). This implies a literal "supported_groups" extension
consisting solely of this group and that there is a
KeyShare extension consisting solely of the value
of the KeyShareEntry.key_exchange (without the length bytes).

SignatureAlgorithms:
: [[TODO]]

HandshakeShape (list):
: specifies the handshake message which appear in the handshake.
When present, the handshake messages are serialized in order without
type or length fields. [[OPEN ISSUE: Not so sure about this.]]


### Serializing Extensions

If an extension has a literal value, then it is not encoded on the
wire at all. The literal value does not include the type and length
bytes.

If an extension has the value null, then it is serialized directly,
but omitting the extension_type value. I.e.,

~~~~
    struct {
        opaque extension_data<0..V>;
    } ListedExtension;
~~~~

The listed extensions MUST be serialized in extension code point
order (this avoids having to carry the extensions code points on
the wire).

Any other extensions are serialized as usual, using the Extension
structure, and can appear in any order.

The corresponding handshake transcript is reconstructed by concatenating:

- The literal-valued extensions in code point order
- The listed extensions in code point order
- Any other extensions in the order they appear on the wire

All of these are encoded using the usual TLS extension encoding.


# Certificate IDs

[[ TODO ]]


# Examples

The following section provides some example specializations.

TLS 1.3 only:
~~~~
{
   “Version” : 0x0304
}
~~~~

TLS 1.3 with AES_GCM and X25519 and ALPN h2, short random values,
and everything else is ordinary TLS 1.3.

{
   “Version” : 0x0304,
   “Random”: 16,
   “CipherSuite” : “TLS_AES_128_GCM_SHA256”,
   "DHGroup": X25519,
   “Extensions”: {
      “named_groups”: “<the hex for X25519”
      “application_layer_protocol_negotiation” : “030016832”,
      “...” : null,
    }
}



# Security Considerations

WARNING: This document is effectively brand new and has seen no
analysis. The idea here is that cTLS is isomorphic to TLS 1.3, and
therefore should provide equivalent security guarantees, modulo use of
new features such as KeyID certificate messages.


One piece that is a new TLS 1.3 feature is the addition of the key_id,
which definitely requires some analysis, especially as it looks like
a potential source of identity misbinding. This is entirely separable
from the rest of the specification. The compression version would also
need further analysis.


# IANA Considerations

IANA is requested to add an extra column to the TLS Supported Groups registry 
to include a mapping for named groups used by cTLS. 



--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
