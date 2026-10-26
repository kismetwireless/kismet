// SPDX-License-Identifier: GPL-2.0-or-later
// LTE EARFCN -> band / band -> duplex -- see lte_band.h.
//
// Transcribed from the reference decoder's EARFCN-range and TDD / SDL / FDD band
// tables. Same row order, same inclusive bounds, same first-hit scan;
// harness/lte_band_verify.py sweeps every EARFCN against the reference table.

#include "lte_band.h"

#include <cstddef>
#include <cstdint>

namespace lte_band {

namespace {

struct Range {
    uint32_t lo;
    uint32_t hi;
    int band;
};

// (low_earfcn, high_earfcn, band) -- the reference EARFCN table, row for row.
const Range kEarfcnBands[] = {
    {    0,   599,  1}, {  600,  1199,  2}, { 1200,  1949,  3}, { 1950,  2399,  4},
    { 2400,  2649,  5}, { 2650,  2749,  6}, { 2750,  3449,  7}, { 3450,  3799,  8},
    { 3800,  4149,  9}, { 4150,  4749, 10}, { 4750,  4949, 11},
    { 5010,  5179, 12}, { 5180,  5279, 13}, { 5280,  5379, 14},
    { 5730,  5849, 17}, { 5850,  5999, 18}, { 6000,  6149, 19},
    { 6150,  6449, 20}, { 6450,  6599, 21}, { 6600,  7399, 22},
    { 7500,  7699, 23}, { 7700,  8039, 24}, { 8040,  8689, 25},
    { 8690,  9039, 26}, { 9040,  9209, 27}, { 9210,  9659, 28},
    { 9660,  9769, 29}, { 9770,  9869, 30}, { 9870,  9919, 31},
    { 9920, 10359, 32}, {36000, 36199, 33}, {36200, 36349, 34},
    {36350, 36949, 35}, {36950, 37549, 36}, {37550, 37749, 37},
    {37750, 38249, 38}, {38250, 38649, 39}, {38650, 39649, 40},
    {39650, 41589, 41}, {41590, 43589, 42}, {43590, 45589, 43},
    {45590, 46589, 44}, {46590, 46789, 45}, {46790, 54539, 46},
    {54540, 55239, 47}, {55240, 56739, 48}, {56740, 58239, 49},
    {58240, 59089, 50}, {59090, 59139, 51}, {59140, 60139, 52},
    {60140, 60254, 53}, {60255, 60304, 54},
    {65536, 66435, 65}, {66436, 67335, 66}, {67336, 67535, 67},
    {67536, 67835, 68}, {67836, 68335, 69}, {68336, 68585, 70},
    {68586, 68935, 71}, {68936, 68985, 72}, {68986, 69035, 73},
    {69036, 69465, 74}, {69466, 70315, 75}, {70316, 70365, 76},
    {70366, 70545, 85}, {70546, 70595, 87}, {70596, 70645, 88},
    {70646, 70655, 103}, {70656, 70705, 106}, {73386, 73485, 111},
};

bool in(int band, const int* set, size_t n) {
    for (size_t i = 0; i < n; i++)
        if (set[i] == band)
            return true;
    return false;
}

// SDL bands = {29, 32, 67, 69, 75, 76}; checked BEFORE FDD, and the FDD set
// excludes them, so an SDL band never reads as FDD.
const int kSdlBands[] = {29, 32, 67, 69, 75, 76};
// FDD bands = 1..28 | {30, 31} | {65, 66, 68, 70..74} | {85, 87, 88, 103, 106, 111},
// minus SDL. There is no LTE band 86.
const int kFddExtra[] = {30, 31, 65, 66, 68, 70, 71, 72, 73, 74, 85, 87, 88, 103, 106, 111};

}  // namespace

int earfcn_to_band(uint32_t earfcn) {
    for (const Range& r : kEarfcnBands)
        if (r.lo <= earfcn && earfcn <= r.hi)
            return r.band;
    return 0;
}

const char* band_to_duplex(int band) {
    if (band >= 33 && band <= 54)                     // _TDD_BANDS = range(33, 55)
        return "TDD";
    if (in(band, kSdlBands, sizeof(kSdlBands) / sizeof(kSdlBands[0])))
        return "SDL";
    if ((band >= 1 && band <= 28) ||
        in(band, kFddExtra, sizeof(kFddExtra) / sizeof(kFddExtra[0])))
        return "FDD";
    return nullptr;
}

}  // namespace lte_band
