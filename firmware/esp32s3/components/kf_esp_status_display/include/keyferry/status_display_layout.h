#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

#include "keyferry/status.h"

namespace keyferry::status::display_layout {

inline constexpr int kGlyphWidth = 5;
inline constexpr int kGlyphHeight = 7;

struct CanvasSize {
  int width;
  int height;
};

using Glyph = std::array<std::uint8_t, kGlyphHeight>;

struct LineLayout {
  int x;
  int y;
  int scale;
};

struct PixelBounds {
  int left;
  int top;
  int right;
  int bottom;
};

Glyph GlyphRows(char character) noexcept;
bool HasGlyph(char character) noexcept;
LineLayout LayoutFor(LineRole role, CanvasSize canvas) noexcept;
PixelBounds BoundsFor(const Line& line, CanvasSize canvas) noexcept;
bool LineFits(const Line& line, CanvasSize canvas) noexcept;
void PaintBlock(std::uint16_t* pixels, int canvas_width, int canvas_height,
                std::size_t block_y, std::size_t block_rows,
                const Presentation& presentation) noexcept;

}  // namespace keyferry::status::display_layout
