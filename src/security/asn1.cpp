#include "gcad/security/asn1.hpp"

namespace gcad::security::asn1 {

std::optional<Element> parse_element(const uint8_t* data, size_t size, size_t offset) noexcept {
    if (!data || offset >= size) return std::nullopt;

    size_t pos = offset;
    const uint8_t tag_byte = data[pos++];

    Element el{};
    el.tag_class = static_cast<TagClass>((tag_byte >> 6) & 0x03);
    el.constructed = (tag_byte & 0x20) != 0;
    uint32_t tag_number = tag_byte & 0x1F;

    if (tag_number == 0x1F) {
        // High-tag-number form (X.690 §8.1.2.4): base-128, MSB=continuation.
        // Not needed by any tag GCAD reads, but parsed correctly rather than
        // rejected outright so an element using it is skipped cleanly, not
        // misread as something else.
        tag_number = 0;
        bool terminated = false;
        for (int i = 0; i < 5 && pos < size; ++i) { // cap iterations: reject absurd tag numbers
            const uint8_t b = data[pos++];
            tag_number = (tag_number << 7) | static_cast<uint32_t>(b & 0x7F);
            if ((b & 0x80) == 0) { terminated = true; break; }
        }
        if (!terminated) return std::nullopt;
    }
    el.tag_number = tag_number;

    if (pos >= size) return std::nullopt;
    const uint8_t len_byte = data[pos++];
    size_t content_length = 0;
    if ((len_byte & 0x80) == 0) {
        content_length = len_byte; // short form
    } else {
        const uint8_t num_len_bytes = len_byte & 0x7F;
        if (num_len_bytes == 0) return std::nullopt; // 0x80 alone = indefinite length: not valid DER
        if (num_len_bytes > sizeof(size_t)) return std::nullopt; // absurdly large: reject
        if (pos + num_len_bytes > size) return std::nullopt;
        for (uint8_t i = 0; i < num_len_bytes; ++i)
            content_length = (content_length << 8) | data[pos++];
    }

    if (content_length > size - pos) return std::nullopt; // declared length exceeds the buffer

    el.content_offset = pos;
    el.content_length = content_length;
    el.total_length = (pos + content_length) - offset;
    return el;
}

std::vector<Element> parse_sequence_children(const uint8_t* data, size_t offset, size_t length) {
    std::vector<Element> children;
    size_t pos = offset;
    const size_t end = offset + length;
    while (pos < end) {
        const auto child = parse_element(data, end, pos);
        if (!child) break; // malformed: stop, keep what parsed cleanly
        children.push_back(*child);
        pos += child->total_length;
    }
    return children;
}

std::vector<uint8_t> read_unsigned_integer(const uint8_t* data, const Element& element) {
    if (!data || !element.is_universal(UniversalTag::INTEGER) || element.content_length == 0)
        return {};
    const uint8_t* content = data + element.content_offset;
    if ((content[0] & 0x80) != 0) return {}; // genuinely negative: never expected here

    size_t start = 0;
    if (element.content_length >= 2 && content[0] == 0x00 && (content[1] & 0x80) != 0)
        start = 1; // strip the DER-mandated pad byte
    return std::vector<uint8_t>(content + start, content + element.content_length);
}

} // namespace gcad::security::asn1
