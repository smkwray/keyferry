#include "keyferry/status_display_layout.h"

#include <algorithm>

namespace keyferry::status::display_layout {
namespace {

constexpr std::uint16_t kBackgroundColor = 0x0000;
constexpr std::uint16_t kPrimaryTextColor = 0xBDF7;
constexpr std::uint16_t kSecondaryTextColor = 0x632C;

std::uint16_t AccentColor(const Activity activity) noexcept {
  switch (activity) {
    case Activity::kReady:
      return 0x2D96;
    case Activity::kActive:
      return 0x35C9;
    case Activity::kConnecting:
    case Activity::kProvisioning:
      return 0xC4C6;
    case Activity::kLocked:
    case Activity::kFault:
      return 0xA9AA;
  }
  return 0xA9AA;
}

std::uint16_t ToneColor(const Tone tone, const Activity activity) noexcept {
  switch (tone) {
    case Tone::kAccent:
      return AccentColor(activity);
    case Tone::kPrimary:
      return kPrimaryTextColor;
    case Tone::kSecondary:
      return kSecondaryTextColor;
  }
  return kPrimaryTextColor;
}

void PaintText(std::uint16_t* pixels, const std::size_t block_y,
               const std::size_t block_rows, const LineLayout layout,
               const int canvas_width, const std::uint16_t color,
               const char* text) noexcept {
  if (pixels == nullptr || text == nullptr) {
    return;
  }
  int cursor_x = layout.x;
  for (const char* current = text; *current != '\0'; ++current) {
    const Glyph glyph = GlyphRows(*current);
    for (int row = 0; row < kGlyphHeight; ++row) {
      for (int column = 0; column < kGlyphWidth; ++column) {
        if ((glyph[row] & (1U << (kGlyphWidth - 1 - column))) == 0) {
          continue;
        }
        for (int dy = 0; dy < layout.scale; ++dy) {
          const int absolute_y = layout.y + row * layout.scale + dy;
          if (absolute_y < static_cast<int>(block_y) ||
              absolute_y >= static_cast<int>(block_y + block_rows)) {
            continue;
          }
          for (int dx = 0; dx < layout.scale; ++dx) {
            const int absolute_x = cursor_x + column * layout.scale + dx;
            if (absolute_x >= 0 && absolute_x < canvas_width) {
              pixels[(absolute_y - static_cast<int>(block_y)) *
                         canvas_width +
                     absolute_x] = color;
            }
          }
        }
      }
    }
    cursor_x += (kGlyphWidth + 1) * layout.scale;
  }
}

}  // namespace

Glyph GlyphRows(const char character) noexcept {
  switch (character) {
    case 'A': return {0x0E, 0x11, 0x11, 0x1F, 0x11, 0x11, 0x11};
    case 'B': return {0x1E, 0x11, 0x11, 0x1E, 0x11, 0x11, 0x1E};
    case 'C': return {0x0E, 0x11, 0x10, 0x10, 0x10, 0x11, 0x0E};
    case 'D': return {0x1E, 0x11, 0x11, 0x11, 0x11, 0x11, 0x1E};
    case 'E': return {0x1F, 0x10, 0x10, 0x1E, 0x10, 0x10, 0x1F};
    case 'F': return {0x1F, 0x10, 0x10, 0x1E, 0x10, 0x10, 0x10};
    case 'G': return {0x0E, 0x11, 0x10, 0x17, 0x11, 0x11, 0x0F};
    case 'H': return {0x11, 0x11, 0x11, 0x1F, 0x11, 0x11, 0x11};
    case 'I': return {0x1F, 0x04, 0x04, 0x04, 0x04, 0x04, 0x1F};
    case 'J': return {0x07, 0x02, 0x02, 0x02, 0x12, 0x12, 0x0C};
    case 'K': return {0x11, 0x12, 0x14, 0x18, 0x14, 0x12, 0x11};
    case 'L': return {0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x1F};
    case 'M': return {0x11, 0x1B, 0x15, 0x15, 0x11, 0x11, 0x11};
    case 'N': return {0x11, 0x19, 0x15, 0x13, 0x11, 0x11, 0x11};
    case 'O': return {0x0E, 0x11, 0x11, 0x11, 0x11, 0x11, 0x0E};
    case 'P': return {0x1E, 0x11, 0x11, 0x1E, 0x10, 0x10, 0x10};
    case 'Q': return {0x0E, 0x11, 0x11, 0x11, 0x15, 0x12, 0x0D};
    case 'R': return {0x1E, 0x11, 0x11, 0x1E, 0x14, 0x12, 0x11};
    case 'S': return {0x0F, 0x10, 0x10, 0x0E, 0x01, 0x01, 0x1E};
    case 'T': return {0x1F, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04};
    case 'U': return {0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x0E};
    case 'V': return {0x11, 0x11, 0x11, 0x11, 0x11, 0x0A, 0x04};
    case 'W': return {0x11, 0x11, 0x11, 0x15, 0x15, 0x15, 0x0A};
    case 'X': return {0x11, 0x11, 0x0A, 0x04, 0x0A, 0x11, 0x11};
    case 'Y': return {0x11, 0x11, 0x0A, 0x04, 0x04, 0x04, 0x04};
    case 'Z': return {0x1F, 0x01, 0x02, 0x04, 0x08, 0x10, 0x1F};
    case '0': return {0x0E, 0x11, 0x13, 0x15, 0x19, 0x11, 0x0E};
    case '1': return {0x04, 0x0C, 0x14, 0x04, 0x04, 0x04, 0x1F};
    case '2': return {0x0E, 0x11, 0x01, 0x02, 0x04, 0x08, 0x1F};
    case '3': return {0x1E, 0x01, 0x01, 0x0E, 0x01, 0x01, 0x1E};
    case '4': return {0x02, 0x06, 0x0A, 0x12, 0x1F, 0x02, 0x02};
    case '5': return {0x1F, 0x10, 0x10, 0x1E, 0x01, 0x01, 0x1E};
    case '6': return {0x0E, 0x10, 0x10, 0x1E, 0x11, 0x11, 0x0E};
    case '7': return {0x1F, 0x01, 0x02, 0x04, 0x08, 0x08, 0x08};
    case '8': return {0x0E, 0x11, 0x11, 0x0E, 0x11, 0x11, 0x0E};
    case '9': return {0x0E, 0x11, 0x11, 0x0F, 0x01, 0x01, 0x0E};
    case '-': return {0x00, 0x00, 0x00, 0x1F, 0x00, 0x00, 0x00};
    case '.': return {0x00, 0x00, 0x00, 0x00, 0x00, 0x0C, 0x0C};
    case ':': return {0x00, 0x0C, 0x0C, 0x00, 0x0C, 0x0C, 0x00};
    case '/': return {0x01, 0x02, 0x02, 0x04, 0x08, 0x08, 0x10};
    default: return {};
  }
}

bool HasGlyph(const char character) noexcept {
  if (character == ' ') {
    return true;
  }
  const Glyph glyph = GlyphRows(character);
  return std::any_of(glyph.begin(), glyph.end(),
                     [](const std::uint8_t row) { return row != 0; });
}

LineLayout LayoutFor(const LineRole role, const CanvasSize canvas) noexcept {
  if (canvas.height <= 80) {
    switch (role) {
      case LineRole::kActivity:
        return {6, 4, 2};
      case LineRole::kDetail:
        return {6, 22, 1};
      case LineRole::kUsb:
        return {6, 35, 1};
      case LineRole::kLink:
        return {6, 48, 1};
      case LineRole::kBuild:
        return {6, 63, 1};
      case LineRole::kDiagnosticHeader:
        return {6, 4, 1};
      case LineRole::kTransport:
        return {6, 17, 1};
      case LineRole::kWifi:
        return {6, 30, 1};
      case LineRole::kBluetooth:
        return {6, 43, 1};
      case LineRole::kHeap:
        return {6, 61, 1};
    }
  }
  switch (role) {
    case LineRole::kActivity:
      return {12, 14, 3};
    case LineRole::kDetail:
      return {12, 46, 1};
    case LineRole::kUsb:
      return {12, 68, 2};
    case LineRole::kLink:
      return {12, 92, 2};
    case LineRole::kBuild:
      return {12, 119, 1};
    case LineRole::kDiagnosticHeader:
      return {12, 8, 1};
    case LineRole::kTransport:
      return {12, 29, 1};
    case LineRole::kWifi:
      return {12, 50, 1};
    case LineRole::kBluetooth:
      return {12, 71, 1};
    case LineRole::kHeap:
      return {12, 99, 1};
  }
  return {0, 0, 1};
}

PixelBounds BoundsFor(const Line& line, const CanvasSize canvas) noexcept {
  const LineLayout layout = LayoutFor(line.role, canvas);
  std::size_t characters = 0;
  while (characters < line.text.size() && line.text[characters] != '\0') {
    ++characters;
  }
  const int width = characters == 0
                        ? 0
                        : static_cast<int>(characters) *
                                  (kGlyphWidth + 1) * layout.scale -
                              layout.scale;
  return {layout.x, layout.y, layout.x + width,
          layout.y + kGlyphHeight * layout.scale};
}

bool LineFits(const Line& line, const CanvasSize canvas) noexcept {
  const PixelBounds bounds = BoundsFor(line, canvas);
  return bounds.left >= 0 && bounds.top >= 0 &&
         bounds.right <= canvas.width && bounds.bottom <= canvas.height;
}

void PaintBlock(std::uint16_t* pixels, const int canvas_width,
                const int canvas_height, const std::size_t block_y,
                const std::size_t block_rows,
                const Presentation& presentation) noexcept {
  if (pixels == nullptr || canvas_width <= 0 || canvas_height <= 0 ||
      block_rows == 0 ||
      block_y + block_rows > static_cast<std::size_t>(canvas_height)) {
    return;
  }
  std::fill(pixels, pixels + block_rows * canvas_width, kBackgroundColor);
  const std::uint16_t accent = AccentColor(presentation.activity());
  for (std::size_t row = 0; row < block_rows; ++row) {
    pixels[row * canvas_width] = accent;
    pixels[row * canvas_width + 1] = accent;
  }
  const CanvasSize canvas{canvas_width, canvas_height};
  for (std::size_t index = 0; index < presentation.line_count(); ++index) {
    const Line& line = presentation.line(index);
    PaintText(pixels, block_y, block_rows, LayoutFor(line.role, canvas),
              canvas_width,
              ToneColor(line.tone, presentation.activity()), line.text.data());
  }
}

}  // namespace keyferry::status::display_layout
