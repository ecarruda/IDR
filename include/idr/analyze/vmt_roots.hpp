#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

#include "idr/pe/image.hpp"
#include "idr/target/target_profile.hpp"

namespace idr::analyze {

// Image addresses (image base + RVA) of the pointer-aligned words that look
// like Delphi class VMTs.
//
// A candidate is any pointer-aligned mapped position `v` whose `vmtClassName`
// field (`profile.vmt().class_name`, a negative offset from the VMT base) holds
// an in-image address `n` where a shortstring of length 1..255 printable ASCII
// bytes starts. Every read goes through `PeFile::at_rva`, so a candidate that
// straddles the end of a section (or points outside the image) is skipped
// silently instead of being read out of bounds; no exception crosses this
// boundary.
//
// A profile without a known `class_name` offset (an unported compiler version)
// has no criterion to apply and therefore yields no candidates.
//
// Sections are visited in PE section-table order, so results are appended in
// that order and every RVA is visited at most once. The section table is not
// required to be sorted by address, so the results are ascending by address
// only for an image whose section table happens to be ascending.
std::vector<uint64_t> find_vmt_roots(const pe::PeFile& image,
                                     const target::TargetProfile& profile);

}  // namespace idr::analyze
