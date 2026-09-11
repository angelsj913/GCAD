#include "gcad/common.hpp"
#include "gcad/security/asn1.hpp"

extern void register_test(const char* name, std::function<bool()> fn);

using gcad::security::asn1::Element;
using gcad::security::asn1::TagClass;
using gcad::security::asn1::UniversalTag;
using gcad::security::asn1::parse_element;
using gcad::security::asn1::parse_sequence_children;
using gcad::security::asn1::read_unsigned_integer;

void register_asn1_tests() {
    register_test("asn1_parses_short_form_integer", [] {
        const std::vector<uint8_t> der = {0x02, 0x01, 0x05}; // INTEGER 5
        const auto el = parse_element(der.data(), der.size(), 0);
        if (!el) return false;
        if (!el->is_universal(UniversalTag::INTEGER)) return false;
        if (el->constructed) return false;
        if (el->content_length != 1 || el->total_length != 3) return false;
        return der[el->content_offset] == 0x05;
    });

    register_test("asn1_parses_sequence_of_two_integers", [] {
        const std::vector<uint8_t> der = {0x30, 0x06, 0x02, 0x01, 0x05, 0x02, 0x01, 0x0A};
        const auto seq = parse_element(der.data(), der.size(), 0);
        if (!seq || !seq->is_universal(UniversalTag::SEQUENCE) || !seq->constructed) return false;
        if (seq->total_length != der.size()) return false;

        const auto children = parse_sequence_children(der.data(), seq->content_offset, seq->content_length);
        if (children.size() != 2) return false;
        return der[children[0].content_offset] == 0x05 && der[children[1].content_offset] == 0x0A;
    });

    register_test("asn1_parses_long_form_length", [] {
        std::vector<uint8_t> der = {0x04, 0x81, 0xC8}; // OCTET STRING, length=200 (long form, 1 length byte)
        der.resize(3 + 200, 0xAB);
        const auto el = parse_element(der.data(), der.size(), 0);
        if (!el) return false;
        if (!el->is_universal(UniversalTag::OCTET_STRING)) return false;
        return el->content_length == 200 && el->total_length == der.size();
    });

    register_test("asn1_rejects_indefinite_length", [] {
        const std::vector<uint8_t> der = {0x30, 0x80, 0x02, 0x01, 0x05, 0x00, 0x00}; // 0x80 = indefinite: not DER
        return !parse_element(der.data(), der.size(), 0).has_value();
    });

    register_test("asn1_rejects_declared_length_exceeding_buffer", [] {
        const std::vector<uint8_t> der = {0x02, 0x05, 0x01, 0x02}; // claims 5 content bytes, only 2 present
        return !parse_element(der.data(), der.size(), 0).has_value();
    });

    register_test("asn1_rejects_truncated_tag", [] {
        const std::vector<uint8_t> der = {};
        return !parse_element(der.data(), der.size(), 0).has_value();
    });

    register_test("asn1_parses_context_specific_constructed_tag", [] {
        // [0] EXPLICIT INTEGER 2 -- the X.509 tbsCertificate "version" field
        // shape: context-specific tag 0, constructed, wrapping an INTEGER.
        const std::vector<uint8_t> der = {0xA0, 0x03, 0x02, 0x01, 0x02};
        const auto el = parse_element(der.data(), der.size(), 0);
        if (!el) return false;
        if (el->tag_class != TagClass::CONTEXT_SPECIFIC || el->tag_number != 0 || !el->constructed)
            return false;
        const auto inner = parse_element(der.data(), der.size(), el->content_offset);
        return inner.has_value() && inner->is_universal(UniversalTag::INTEGER) &&
               der[inner->content_offset] == 0x02;
    });

    register_test("asn1_read_unsigned_integer_strips_padding_byte", [] {
        // INTEGER 128 must be encoded with a leading 0x00 pad (0x80 alone
        // would read as -128 in two's complement).
        const std::vector<uint8_t> der = {0x02, 0x02, 0x00, 0x80};
        const auto el = parse_element(der.data(), der.size(), 0);
        if (!el) return false;
        const auto value = read_unsigned_integer(der.data(), *el);
        return value.size() == 1 && value[0] == 0x80;
    });

    register_test("asn1_read_unsigned_integer_keeps_bytes_without_padding", [] {
        const std::vector<uint8_t> der = {0x02, 0x02, 0x01, 0x2C}; // INTEGER 300, no pad needed
        const auto el = parse_element(der.data(), der.size(), 0);
        if (!el) return false;
        const auto value = read_unsigned_integer(der.data(), *el);
        return value.size() == 2 && value[0] == 0x01 && value[1] == 0x2C;
    });

    register_test("asn1_read_unsigned_integer_rejects_negative", [] {
        const std::vector<uint8_t> der = {0x02, 0x01, 0x80}; // INTEGER -128, no pad byte: genuinely negative
        const auto el = parse_element(der.data(), der.size(), 0);
        if (!el) return false;
        return read_unsigned_integer(der.data(), *el).empty();
    });

    register_test("asn1_parses_object_identifier_bytes_without_interpreting_them", [] {
        // sha256WithRSAEncryption: 1.2.840.113549.1.1.11
        const std::vector<uint8_t> der = {0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B};
        const auto el = parse_element(der.data(), der.size(), 0);
        if (!el) return false;
        if (!el->is_universal(UniversalTag::OBJECT_IDENTIFIER)) return false;
        return el->content_length == 9 && el->total_length == der.size();
    });

    register_test("asn1_parse_sequence_children_stops_cleanly_on_malformed_child", [] {
        // A well-formed first child (INTEGER 5) followed by a second child
        // whose declared length overruns the parent's own content bounds.
        const std::vector<uint8_t> der = {0x02, 0x01, 0x05, 0x02, 0x05, 0x01};
        const auto children = parse_sequence_children(der.data(), 0, der.size());
        return children.size() == 1;
    });
}
