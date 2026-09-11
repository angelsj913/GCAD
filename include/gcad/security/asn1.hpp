#pragma once

#include "../common.hpp"

namespace gcad::security::asn1 {

// Minimal DER (Distinguished Encoding Rules, ITU-T X.690) reader: the
// building block for parsing X.509 certificates and PKCS#7/CMS SignedData
// (the Authenticode signature blob) directly, instead of calling
// CertGetCertificateChain/WinVerifyTrust to have Windows make the trust
// decision on GCAD's behalf. This layer only understands DER's TLV
// structure -- it does not interpret certificate or signature semantics.
//
// Every function fails closed: malformed, truncated, or indefinite-length
// (valid in BER, never in DER) input yields nullopt/an empty result rather
// than a guessed value, matching every other parser in this codebase.

enum class TagClass : uint8_t {
    UNIVERSAL        = 0,
    APPLICATION      = 1,
    CONTEXT_SPECIFIC = 2,
    PRIVATE          = 3,
};

// Universal tag numbers actually used while parsing X.509/PKCS#7 (X.680 §8).
enum class UniversalTag : uint32_t {
    BOOLEAN            = 1,
    INTEGER            = 2,
    BIT_STRING         = 3,
    OCTET_STRING       = 4,
    NULL_TAG           = 5,
    OBJECT_IDENTIFIER  = 6,
    UTF8_STRING        = 12,
    SEQUENCE           = 16,
    SET                = 17,
    PRINTABLE_STRING   = 19,
    T61_STRING         = 20,
    IA5_STRING         = 22,
    UTC_TIME           = 23,
    GENERALIZED_TIME   = 24,
    BMP_STRING         = 30,
};

struct Element {
    TagClass tag_class{TagClass::UNIVERSAL};
    bool     constructed{false};
    uint32_t tag_number{0};
    size_t   content_offset{0}; // offset into the buffer parse_element() was given
    size_t   content_length{0};
    size_t   total_length{0};   // tag + length + content bytes this element occupies

    bool is_universal(UniversalTag t) const noexcept {
        return tag_class == TagClass::UNIVERSAL && tag_number == static_cast<uint32_t>(t);
    }
};

// Parses one DER TLV starting at `offset` within `data`/`size`. Rejects
// indefinite-length encoding (0x80 length byte alone -- valid BER, never
// valid DER), a declared length exceeding the remaining buffer, and a
// truncated tag/length. `size` bounds the search, not necessarily the whole
// original buffer, so nested content can be parsed by passing a narrowed
// `size`.
std::optional<Element> parse_element(const uint8_t* data, size_t size, size_t offset) noexcept;

// Iterates sibling TLVs within [offset, offset+length) -- e.g. the direct
// children of a SEQUENCE/SET's content region. Stops at the first malformed
// child and returns what parsed cleanly before it, rather than discarding
// everything or guessing past the corruption.
std::vector<Element> parse_sequence_children(const uint8_t* data, size_t offset, size_t length);

// Reads a DER INTEGER's content as an unsigned big-endian byte string. DER
// INTEGER is two's-complement, so a value whose high bit would otherwise read
// as a sign bit carries a leading 0x00 pad byte; this strips that byte when
// present. Returns empty for a non-INTEGER element or a genuinely negative
// value -- nothing GCAD reads from a certificate (serial numbers, RSA
// modulus/exponent) is ever legitimately negative.
std::vector<uint8_t> read_unsigned_integer(const uint8_t* data, const Element& element);

// Returns this element's complete TLV encoding (tag + length + content) as
// raw bytes -- needed to re-embed or hash a nested structure exactly as it
// was encoded (e.g. Authenticode's signature covers the DER encoding of a
// specific inner SEQUENCE, not just its content).
std::vector<uint8_t> raw_bytes(const uint8_t* data, const Element& element);

// Decodes an OBJECT IDENTIFIER's content into dotted-decimal form (e.g.
// "1.2.840.113549.1.1.11"), per X.690 §8.19. Returns empty for a non-OID
// element or malformed content (a final byte with the continuation bit set).
std::string oid_to_string(const uint8_t* data, const Element& element);

} // namespace gcad::security::asn1
