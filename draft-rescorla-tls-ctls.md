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

 -
    ins: H. Tschofenig
    name: Hannes Tschofenig
    organization: Arm Limited
    email: hannes.tschofenig@arm.com

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
is achieved by four basic techniques:

- Omitting unnecessary values that are a holdover from previous versions
  of TLS.
- Omitting the fields and handshake messages required for preserving backwards-compatibility
  with earlier TLS versions.
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

[[OPEN ISSUE: Should we just re-encode this directly in CBOR?.
That might be easier for people, but I ran out of time.]]

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

~~~~
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
~~~~

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
supported_versions extension can be omitted.

Importantly, this process is performed only for the wire encoding but
not for the handshake transcript.  The result is that the transcript for a
specialized cTLS handshake is the same as the transcript for a TLS 1.3 handshake
with the same features used. [[OPEN ISSUE: Except possibly inserting sme
extension indicating the use of cTLS.]]

One way of thinking of this is as if specialization is a stateful compression
layer between the handshake and the record layer:

~~~~~
+---------------+---------------+---------------+
|   Handshake   |  Application  |     Alert     |
+---------------+---------------+---------------+    +---------+
|               cTLS Compression Layer          |<---| Profile |
+---------------+---------------+---------------+    +---------+
|          cTLS Record Layer / Application      |
+---------------+---------------+---------------+
~~~~~

Specializations are defined by a "compression profile" that specifies what
features are to be optimized out of the handshake.  In the following
subsections, we define the structure of these profiles, and how they are used in
compressing and decompressing handshake messages.

## Specifying a Specialization

A compression profile defining of a specialized version of TLS is
defined using a JSON dictionary. Each axis of specialization
is a key in the dictionary. [[OPEN ISSUE: If we ever want to
serialize this, we'll want to use a list instead.]].

For example, the following specialization describes a protocol
with a single fixed version (TLS 1.3) and a single fixed
cipher suite (TLS_AES_128_GCM_SHA256). On the wire, ClientHello.cipher_suites,
ServerHello.cipher_suites, and the supported_versions extensions in the
ClientHello and ServerHello would be omitted.

~~~~
{
   "version" : 772,
   "cipherSuite" : "TLS_AES_128_GCM_SHA256"
}
~~~~

cTLS allows specialization along the following axes:

version (integer):
: indicates that both sides agree to the
single TLS version specified by the given integer value
(772 == 0x0304 for TLS 1.3). The supported_versions extension
is omitted from ClientHello.extensions and reconstructed in the transcript as a
single-valued list with the specified value. The supported_versions extension is
omitted from ClientHello.extensions and reconstructed in the transcript with the
specified value.

cipherSuite (string):
: indicates that both sides agree to
the single named cipher suite, using the "TLS_AEAD_HASH" syntax
defined in {{RFC8446}}, Section 8.4. The ClientHello.cipher_suites
field is omitted and reconstructed in the transcript as a single-valued
list with the specified value. The server_hello.cipher_suite field is
omitted and reconstructed in the transcript as the specified value.

dhGroup (string):
: specifies a single DH group to use for key establishment. The
group is listed by the code point name in {{RFC8446}}, Section 4.2.7.
(e.g., x25519). This implies a literal "supported_groups" extension
consisting solely of this group.

signatureAlgorithm (string):
: specifies a single signature scheme to use for authentication. The
group is listed by the code point name in {{RFC8446}}, Section 4.2.7.
(e.g., x25519). This implies a literal "signature_algorithms" extension
consisting solely of this group.

randomSize (integer):
: indicates that the ClientHello.Random and ServerHello.Random values
are truncated to the given values. When the transcript is
reconstructed, the Random is padded to the right with 0s and the
anti-downgrade mechanism in {{RFC8446)}, Section 4.1.3 is disabled.
IMPORTANT: Using short Random values can lead to potential
attacks. When Random values are shorter than 8 bytes, PSK-only modes
MUST NOT be used, and each side MUST use fresh DH ephemerals.
The Random length MUST be less than or equal to 32 bytes.

clientHelloExtensions (predefined extensions):
: Predefined ClientHello extensions, see {predefined-extensions}

serverHelloExtensions (predefined extensions):
: Predefined ServerHello extensions, see {predefined-extensions}

encryptedExtensions (predefined extensions):
: Predefined EncryptedExtensions extensions, see {predefined-extensions}

certRequestExtensions (predefined extensions):
: Predefined CertificateRequest extensions, see {predefined-extensions}

knownCertificates (known certificates):
: A compression dictionary for the Certificate message, see {known-certs}

finishedSize (integer):
: indicates that the Finished value is to be truncated to the given
length. When the transcript is reconstructed, the remainder of the
Finished value is filled in by the receiving side.
[[OPEN ISSUE: How short should we allow this to be?]]

### Requirements on the TLS Implementation

To be compatible with the specializations described in this section, a
TLS stack needs to provide two key features:

If specialization of extensions is to be used, then the TLS stack MUST order
each vector of Extension values in ascending order according to the
ExtensionType.  This allows for a deterministic reconstruction of the extension
list.

If truncated Random values are to be used, then the TLS stack MUST be
configurable to set the remaining bytes of the random values to zero.  This
ensures that the reconstructed, padded random value matches the original.

If truncated Finished values are to be used, then the TLS stack MUST be
configurable so that only the provided bytes of the Finished are verified.

### Predefined Extensions

Extensions used in the ClientHello, ServerHello, EncryptedExtensions, and
CertificateRequest messages can be "predefined" in a compression profile, so
that they do not have to be sent on the wire.  A predefined extensions object is
a dictionary whose keys are extension names specified in the TLS
ExtensionTypeRegistry specified in {{RFC8446}}.  The corresponding value is a
hex-encoded value for the ExtensionData field of the extension.

When compressing a handshake message, the sender compares the extensions in the
message being compressed to the predefined extensions object, applying the
following rules:

* If the extensions list in the message is not sorted in ascending order by
  extension type, it is an error, because the decompressed message will not
  match.
* If there is no entry in the predefined extensions object for the type of the
  extension, then the extension is included in the compressed message
* If there is an entry:
    * If the ExtensionData of the extension does not match the value in the
      dictionary, it is an error, because decompression will not produce the
      correct result.
    * If the ExtensionData matches, then the extension is removed, and not
      included in the compressed message.

When decompressing a handshake message the receiver reconstitutes the original
extensions list using the predefined extensions:

* If there is an extension in the compressed message with a type that exists in
  the predefined extensions object, it is an error, because such an extension
  would not have been sent by a sender with a compatible compression profile.
* For each entry in the predefined extensions dictionary, an extension is added
  to the decompressed message with the specified type and value.
* The resulting vector of extensions MUST be sorted in ascending order by
  extension type.

Note that the "version", "dhGroup", and "signatureAlgorithm" fields in the
compression profile are specific instances of this algorithm for the
corresponding extensions.

### Known Certificates {#known-certs}

Certificates are a major contributor to the size of a TLS handshake.  In order
to avoid this overhead when the parties to a handshake have already exchanged
certificates, a compression profile can specify a dictionary of "known
certificates" that effectively acts as a compression dictionary on certificates.

A known certicates object is a JSON dictionary whose keys are strings containing
hex-encoded compressed values.  The corresponding values are hex-encoded strings
representing the uncompressed values.  For example:

~~~~~
{
  "00": "3082...",
  "01": "3082...",
}
~~~~~

When compressing a Certificate message, the sender examines the cert_data field
of each CertificateEntry.  If the cert_data matches a value in the known
certificates object, then the sender replaces the cert_data with the
corresponding key.  Decompression works the opposite way, replacing keys with
values.

Note that in this scheme, there is no signaling on the wire for whether a given
cert_data value is compressed or uncompressed.  Known certificates objects
should be constructed in such a way as to avoid a uncompressed object being
mistaken for compressed one and erroneously decompressed.  For X.509, it is
sufficient for the first byte of the compressed value (key) to have a value
other than 0x30, since every X.509 certificate starts with this byte.

# Examples

The following section provides some example specializations.

TLS 1.3 only:
~~~~
{
   "Version" : 0x0304
}
~~~~

TLS 1.3 with AES_GCM and X25519 and ALPN h2, short random values,
and everything else is ordinary TLS 1.3.

{
   "Version" : 772,
   "Random": 16,
   "CipherSuite" : "TLS_AES_128_GCM_SHA256",
   "DHGroup": "X25519",
   "Extensions": {
      "named_groups": 29,
      "application_layer_protocol_negotiation" : "030016832",
      "..." : null
    }
}

Version 772 corresponds to the hex representation 0x0304, named group "29" 
(0x001D) represents X25519.

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

This document has no IANA actions.



--- back

# Acknowledgments
{:numbered="false"}

We would like to thank Karthikeyan Bhargavan, Owen Friel, Sean Turner, Martin Thomson and Chris Wood.
