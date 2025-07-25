/// Performs NFKD - Compatibility decomposition for Unicode according
/// to rules in ftp://ftp.unicode.org/Public/UNIDATA/UnicodeData.txt
/// This beautiful code has been inspired by Zurich area in 2011 (Alexander Borsuk).

#include "base/string_utils.hpp"

namespace strings
{

UniChar constexpr normSymbols[] = {
    0x635,   0x644,   0x649,  0x20,   0x627,   0x644,   0x644,  0x647,  0x20,    0x639,   0x644,   0x64a,   0x647,
    0x20,    0x648,   0x633,  0x644,  0x645,   0x62c,   0x644,  0x20,   0x62c,   0x644,   0x627,   0x644,   0x647,
    0x28,    0x110b,  0x1169, 0x110c, 0x1165,  0x11ab,  0x29,   0x28,   0x110b,  0x1169,  0x1112,  0x116e,  0x29,
    0x72,    0x61,    0x64,   0x2215, 0x73,    0x32,    0x30ad, 0x30ed, 0x30e1,  0x30fc,  0x30c8,  0x30eb,  0x30ec,
    0x30f3,  0x30c8,  0x30b1, 0x30f3, 0x30d5,  0x30a1,  0x30e9, 0x30c3, 0x30c8,  0x30d2,  0x30a2,  0x30b9,  0x30c8,
    0x30eb,  0x30cf,  0x30fc, 0x30bb, 0x30f3,  0x30c8,  0x30b5, 0x30f3, 0x30c1,  0x30fc,  0x30e0,  0x30df,  0x30ea,
    0x30cf,  0x30fc,  0x30eb, 0x30af, 0x30eb,  0x30bb,  0x30a4, 0x30ed, 0x30af,  0x30e9,  0x30e0,  0x30c8,  0x30f3,
    0x30ad,  0x30ed,  0x30ef, 0x30c3, 0x30c8,  0x30ad,  0x30ed, 0x30af, 0x30e9,  0x30e0,  0x30de,  0x30f3,  0x30b7,
    0x30e7,  0x30f3,  0x30a8, 0x30b9, 0x30af,  0x30fc,  0x30c8, 0x30d8, 0x30af,  0x30bf,  0x30fc,  0x30eb,  0x30d5,
    0x30c3,  0x30b7,  0x30a7, 0x30eb, 0x110e,  0x1161,  0x11b7, 0x1100, 0x1169,  0x30df,  0x30af,  0x30ed,  0x30f3,
    0x2032,  0x2032,  0x2032, 0x2032, 0x30e1,  0x30ab,  0x30c8, 0x30f3, 0x30de,  0x30a4,  0x30af,  0x30ed,  0x30db,
    0x30a4,  0x30f3,  0x30c8, 0x30ea, 0x30c3,  0x30c8,  0x30eb, 0x30d5, 0x30a3,  0x30fc,  0x30c8,  0x30eb,  0x30fc,
    0x30d5,  0x30eb,  0x31,   0x2044, 0x31,    0x30,    0x56,   0x49,   0x49,    0x49,    0x76,    0x69,    0x69,
    0x69,    0x28,    0x31,   0x30,   0x29,    0x28,    0x31,   0x31,   0x29,    0x28,    0x31,    0x32,    0x29,
    0x28,    0x31,    0x33,   0x29,   0x28,    0x31,    0x34,   0x29,   0x28,    0x31,    0x35,    0x29,    0x28,
    0x31,    0x36,    0x29,   0x28,   0x31,    0x37,    0x29,   0x28,   0x31,    0x38,    0x29,    0x28,    0x31,
    0x39,    0x29,    0x28,   0x32,   0x30,    0x29,    0x110c, 0x116e, 0x110b,  0x1174,  0x30a2,  0x30cf,  0x30fc,
    0x30c8,  0x30a2,  0x30eb, 0x30d5, 0x30a1,  0x30a2,  0x30f3, 0x30d8, 0x30a2,  0x30a4,  0x30cb,  0x30f3,  0x30af,
    0x30a8,  0x30fc,  0x30ab, 0x30fc, 0x30ab,  0x30e9,  0x30c3, 0x30c8, 0x30ab,  0x30ed,  0x30ea,  0x30fc,  0x30ad,
    0x30e5,  0x30ea,  0x30fc, 0x30ad, 0x30eb,  0x30bf,  0x30fc, 0x30af, 0x30ed,  0x30fc,  0x30cd,  0x30b5,  0x30a4,
    0x30af,  0x30eb,  0x30b7, 0x30ea, 0x30f3,  0x30af,  0x30cf, 0x30fc, 0x30ec,  0x30eb,  0x28,    0x110c,  0x116e,
    0x29,    0x28,    0x1112, 0x1161, 0x29,    0x28,    0x1111, 0x1161, 0x29,    0x28,    0x1110,  0x1161,  0x29,
    0x28,    0x110f,  0x1161, 0x29,   0x28,    0x110e,  0x1161, 0x29,   0x28,    0x110c,  0x1161,  0x29,    0x28,
    0x110b,  0x1161,  0x29,   0x28,   0x1109,  0x1161,  0x29,   0x28,   0x1107,  0x1161,  0x29,    0x28,    0x1106,
    0x1161,  0x29,    0x28,   0x1105, 0x1161,  0x29,    0x28,   0x1103, 0x1161,  0x29,    0x28,    0x1102,  0x1161,
    0x29,    0x28,    0x1100, 0x1161, 0x29,    0x6b,    0x63,   0x61,   0x6c,    0x6d,    0x2215,  0x73,    0x32,
    0x631,   0x6cc,   0x627,  0x644,  0x631,   0x633,   0x648,  0x644,  0x61,    0x2e,    0x6d,    0x2e,    0x635,
    0x644,   0x639,   0x645,  0x645,  0x62d,   0x645,   0x62f,  0x43,   0x2215,  0x6b,    0x67,    0x627,   0x643,
    0x628,   0x631,   0x70,   0x2e,   0x6d,    0x2e,    0x222b, 0x222b, 0x222b,  0x222b,  0x633,   0x645,   0x62d,
    0x633,   0x645,   0x62c,  0x68,   0x50,    0x61,    0x62,   0x61,   0x72,    0x64,    0x6d,    0x32,    0x2e,
    0x2e,    0x2e,    0x64,   0x6d,   0x33,    0x639,   0x62c,  0x645,  0x6b,    0x48,    0x7a,    0x4d,    0x48,
    0x7a,    0x47,    0x48,   0x7a,   0x54,    0x48,    0x7a,   0x6d,   0x6d,    0x32,    0x63,    0x6d,    0x32,
    0x30d2,  0x30af,  0x30eb, 0x6b,   0x6d,    0x32,    0x642,  0x644,  0x6d2,   0x30de,  0x30a4,  0x30eb,  0x30db,
    0x30fc,  0x30f3,  0x30db, 0x30fc, 0x30eb,  0x30db,  0x30f3, 0x30c8, 0x30db,  0x30eb,  0x30c8,  0x30de,  0x30c3,
    0x30cf,  0x30d8,  0x30fc, 0x30bf, 0x30d8,  0x30fc,  0x30b7, 0x30d8, 0x30f3,  0x30b9,  0x30d8,  0x30eb,  0x30c4,
    0x30d8,  0x30cb,  0x30d2, 0x30de, 0x30eb,  0x30af,  0x635,  0x644,  0x6d2,   0x30d5,  0x30e9,  0x30f3,  0x646,
    0x62c,   0x64a,   0x633,  0x62e,  0x64a,   0x635,   0x645,  0x645,  0x633,   0x62c,   0x649,   0x43,    0x6f,
    0x2e,    0x30ab,  0x30a4, 0x30ea, 0x30aa,  0x30fc,  0x30e0, 0x30aa, 0x30f3,  0x30b9,  0x41,    0x2215,  0x6d,
    0x56,    0x2215,  0x6d,   0x30a6, 0x30a9,  0x30f3,  0x30a4, 0x30f3, 0x30c1,  0x6c,    0x6f,    0x67,    0x30a2,
    0x30fc,  0x30eb,  0x50,   0x50,   0x4d,    0x6d,    0x6f,   0x6c,   0x4c,    0x54,    0x44,    0x65,    0x72,
    0x67,    0x633,   0x62c,  0x62d,  0x633,   0x62d,   0x62c,  0x62d,  0x645,   0x649,   0x62d,   0x645,   0x64a,
    0x62c,   0x645,   0x62d,  0x62c,  0x645,   0x62d,   0x62a,  0x645,  0x62e,   0x62a,   0x645,   0x62d,   0x62a,
    0x645,   0x62c,   0x6d,   0x69,   0x6c,    0x6d,    0x6d,   0x33,   0x30cf,  0x30fc,  0x30c4,  0x63,    0x6d,
    0x33,    0x30cf,  0x30a4, 0x30c4, 0x30ce,  0x30c3,  0x30c8, 0x30bf, 0x30fc,  0x30b9,  0x30bb,  0x30f3,  0x30c1,
    0x6b,    0x6d,    0x33,   0x30b3, 0x30fc,  0x30db,  0x30b3, 0x30eb, 0x30ca,  0x30b1,  0x30fc,  0x30b9,  0x6b,
    0x50,    0x61,    0x4d,   0x50,   0x61,    0x47,    0x50,   0x61,   0x66,    0x66,    0x6c,    0x66,    0x66,
    0x69,    0x67,    0x61,   0x6c,   0x30ad,  0x30cb,  0x30fc, 0x30ab, 0x30f3,  0x30de,  0x30ab,  0x30ed,  0x30f3,
    0x62a,   0x645,   0x64a,  0x62a,  0x62e,   0x649,   0x62a,  0x62e,  0x64a,   0x62a,   0x62c,   0x649,   0x62a,
    0x62c,   0x64a,   0x628,  0x62e,  0x64a,   0x64a,   0x645,  0x645,  0x64a,   0x645,   0x645,   0x646,   0x645,
    0x649,   0x646,   0x645,  0x64a,  0x646,   0x62c,   0x649,  0x646,  0x62c,   0x645,   0x646,   0x62c,   0x645,
    0x646,   0x62d,   0x649,  0x646,  0x62d,   0x645,   0x647,  0x645,  0x645,   0x647,   0x645,   0x62c,   0x645,
    0x62c,   0x62e,   0x645,  0x62e,  0x645,   0x645,   0x62e,  0x62c,  0x645,   0x62c,   0x62d,   0x645,   0x62d,
    0x64a,   0x646,   0x62c,  0x62d,  0x64a,   0x645,   0x64a,  0x64a,  0x62c,   0x64a,   0x64a,   0x62d,   0x64a,
    0x644,   0x645,   0x64a,  0x644,  0x62c,   0x64a,   0x636,  0x62d,  0x64a,   0x642,   0x645,   0x64a,   0x646,
    0x62d,   0x64a,   0x642,  0x645,  0x62d,   0x644,   0x62d,  0x645,  0x639,   0x645,   0x64a,   0x643,   0x645,
    0x64a,   0x645,   0x62e,  0x64a,  0x644,   0x62c,   0x645,  0x643,  0x645,   0x645,   0x634,   0x62d,   0x64a,
    0x635,   0x62d,   0x64a,  0x633,  0x62e,   0x649,   0x62c,  0x645,  0x649,   0x62c,   0x62d,   0x649,   0x62c,
    0x645,   0x64a,   0x62a,  0x645,  0x649,   0x636,   0x62e,  0x645,  0x636,   0x62e,   0x645,   0x636,   0x62d,
    0x649,   0x62d,   0x62c,  0x64a,  0x634,   0x645,   0x645,  0x634,  0x645,   0x645,   0x634,   0x645,   0x62e,
    0x634,   0x645,   0x62e,  0x634,  0x62c,   0x64a,   0x634,  0x62d,  0x645,   0x634,   0x62d,   0x645,   0x635,
    0x62d,   0x62d,   0x635,  0x62d,  0x62d,   0x633,   0x645,  0x645,  0x633,   0x645,   0x645,   0x645,   0x62c,
    0x64a,   0x641,   0x645,  0x64a,  0x30eb,  0x30d2,  0x30fc, 0x628,  0x62d,   0x64a,   0x30e6,  0x30a2,  0x30f3,
    0x30e4,  0x30fc,  0x30eb, 0x30e4, 0x30fc,  0x30c8,  0x644,  0x645,  0x62d,   0x644,   0x645,   0x62d,   0x644,
    0x62e,   0x645,   0x644,  0x62e,  0x645,   0x644,   0x62c,  0x62c,  0x644,   0x62c,   0x62c,   0x644,   0x62d,
    0x649,   0x644,   0x62d,  0x64a,  0x642,   0x645,   0x645,  0x641,  0x62e,   0x645,   0x641,   0x62e,   0x645,
    0x63a,   0x645,   0x649,  0x63a,  0x645,   0x64a,   0x63a,  0x645,  0x645,   0x639,   0x645,   0x649,   0x637,
    0x645,   0x64a,   0x637,  0x645,  0x645,   0x637,   0x645,  0x62d,  0x637,   0x645,   0x62d,   0x58,    0x49,
    0x49,    0x78,    0x69,   0x69,   0x30,    0x2044,  0x33,   0x222e, 0x222e,  0x222e,  0x28,    0x31,    0x29,
    0x28,    0x32,    0x29,   0x28,   0x33,    0x29,    0x28,   0x34,   0x29,    0x28,    0x35,    0x29,    0x28,
    0x36,    0x29,    0x28,   0x37,   0x29,    0x28,    0x38,   0x29,   0x28,    0x39,    0x29,    0x28,    0x41,
    0x29,    0x28,    0x42,   0x29,   0x28,    0x43,    0x29,   0x28,   0x44,    0x29,    0x28,    0x45,    0x29,
    0x28,    0x46,    0x29,   0x28,   0x47,    0x29,    0x28,   0x48,   0x29,    0x28,    0x49,    0x29,    0x28,
    0x4a,    0x29,    0x28,   0x4b,   0x29,    0x28,    0x1106, 0x29,   0x28,    0x1105,  0x29,    0x28,    0x1103,
    0x29,    0x28,    0x1102, 0x29,   0x28,    0x1100,  0x29,   0x61,   0x2f,    0x63,    0x61,    0x2f,    0x73,
    0x63,    0x2f,    0x6f,   0x63,   0x2f,    0x75,    0x54,   0x45,   0x4c,    0x62a,   0x62d,   0x645,   0x46,
    0x41,    0x58,    0x31,   0x2044, 0x37,    0x31,    0x2044, 0x39,   0x31,    0x2044,  0x33,    0x32,    0x2044,
    0x33,    0x31,    0x2044, 0x35,   0x32,    0x2044,  0x35,   0x33,   0x2044,  0x35,    0x34,    0x2044,  0x35,
    0x31,    0x2044,  0x36,   0x35,   0x2044,  0x36,    0x31,   0x2044, 0x38,    0x33,    0x2044,  0x38,    0x35,
    0x2044,  0x38,    0x37,   0x2044, 0x38,    0x62a,   0x62d,  0x62c,  0x62a,   0x62d,   0x62c,   0x62a,   0x62c,
    0x645,   0x28,    0x64,   0x29,   0x28,    0x65,    0x29,   0x28,   0x66,    0x29,    0x28,    0x67,    0x29,
    0x28,    0x68,    0x29,   0x28,   0x69,    0x29,    0x28,   0x6a,   0x29,    0x28,    0x6b,    0x29,    0x28,
    0x6c,    0x29,    0x28,   0x6d,   0x29,    0x28,    0x6e,   0x29,   0x50,    0x50,    0x56,    0x28,    0x6f,
    0x29,    0x28,    0x70,   0x29,   0x28,    0x71,    0x29,   0x28,   0x72,    0x29,    0x28,    0x73,    0x29,
    0x33,    0x2044,  0x34,   0x31,   0x2044,  0x32,    0x31,   0x2044, 0x34,    0x28,    0x74,    0x29,    0x28,
    0x75,    0x29,    0x28,   0x76,   0x29,    0x28,    0x77,   0x29,   0x28,    0x78,    0x29,    0x28,    0x79,
    0x29,    0x28,    0x7a,   0x29,   0x3d,    0x3d,    0x3d,   0x3a,   0x3a,    0x3d,    0x28,    0x4c,    0x29,
    0x28,    0x4d,    0x29,   0x28,   0x4e,    0x29,    0x28,   0x4f,   0x29,    0x28,    0x50,    0x29,    0x28,
    0x51,    0x29,    0x28,   0x52,   0x29,    0x28,    0x53,   0x29,   0x28,    0x54,    0x29,    0x28,    0x55,
    0x29,    0x28,    0x56,   0x29,   0x28,    0x57,    0x29,   0x28,   0x58,    0x29,    0x28,    0x59,    0x29,
    0x28,    0x5a,    0x29,   0x3014, 0x53,    0x3015,  0x31,   0x30,   0x2e,    0x31,    0x31,    0x2e,    0x31,
    0x32,    0x2e,    0x31,   0x33,   0x2e,    0x31,    0x34,   0x2e,   0x31,    0x35,    0x2e,    0x31,    0x36,
    0x2e,    0x31,    0x37,   0x2e,   0x31,    0x38,    0x2e,   0x31,   0x39,    0x2e,    0x32,    0x30,    0x2e,
    0x28,    0x61,    0x29,   0x28,   0x62,    0x29,    0x28,   0x63,   0x29,    0x62a,   0x62e,   0x645,   0x28,
    0x4e00,  0x29,    0x28,   0x1112, 0x29,    0x28,    0x1111, 0x29,   0x28,    0x1110,  0x29,    0x28,    0x110f,
    0x29,    0x50,    0x54,   0x45,   0x28,    0x1109,  0x29,   0x28,   0x110e,  0x29,    0x2035,  0x2035,  0x2035,
    0x28,    0x110c,  0x29,   0x28,   0x1107,  0x29,    0x28,   0x110b, 0x29,    0x3bc,   0x67,    0x3bc,   0x46,
    0x6e,    0x46,    0x70,   0x46,   0x34,    0x33,    0x6d,   0x67,   0x61,    0x2be,   0x3bc,   0x6d,    0x6e,
    0x6d,    0x66,    0x6d,   0x6b,   0x6c,    0x64,    0x6c,   0x6d,   0x6c,    0x3bc,   0x6c,    0x33,    0x30,
    0x32,    0x39,    0x32,   0x38,   0x34,    0x32,    0x32,   0x37,   0x48,    0x67,    0x35,    0x30,    0x32,
    0x33,    0x32,    0x34,   0x34,   0x39,    0x64,    0x61,   0x41,   0x55,    0x47,    0x42,    0x4d,    0x42,
    0x4b,    0x42,    0x6b,   0x41,   0x6d,    0x41,    0x3bc,  0x41,   0x6e,    0x41,    0x70,    0x41,    0x49,
    0x55,    0x34,    0x35,   0x34,   0x36,    0x34,    0x37,   0x70,   0x63,    0x6f,    0x56,    0x34,    0x38,
    0x6d,    0x57,    0x6b,   0x57,   0x4d,    0x57,    0x6b,   0x3a9,  0x4d,    0x3a9,   0x42,    0x71,    0x63,
    0x63,    0x63,    0x64,   0x64,   0x42,    0x47,    0x79,   0x68,   0x61,    0x48,    0x50,    0x69,    0x6e,
    0x4b,    0x4b,    0x4b,   0x4d,   0x6b,    0x74,    0x6c,   0x6e,   0x6c,    0x78,    0x6d,    0x62,    0x33,
    0x33,    0x33,    0x34,   0x33,   0x35,    0x34,    0x30,   0x33,   0x39,    0x33,    0x38,    0x33,    0x37,
    0x33,    0x36,    0x110b, 0x116e, 0x70,    0x73,    0x6e,   0x73,   0x3bc,   0x73,    0x6d,    0x73,    0x70,
    0x56,    0x6e,    0x56,   0x3bc,  0x56,    0x6b,    0x56,   0x4d,   0x56,    0x70,    0x57,    0x6e,    0x57,
    0x3bc,   0x57,    0x30d8, 0x30bd, 0x30d2,  0x30eb,  0x30d2, 0x30b3, 0x28,    0x29,    0x28,    0x29,    0x49,
    0x56,    0x49,    0x58,   0x30ca, 0x30ce,  0x69,    0x76,   0x21,   0x3f,    0x3f,    0x21,    0x21,    0x21,
    0x52,    0x73,    0xb0,   0x43,   0xb0,    0x46,    0x30ea, 0x30e9, 0x4e,    0x6f,    0x30ec,  0x30e0,  0x53,
    0x4d,    0x54,    0x4d,   0x30ad, 0x30ab,  0x32,    0x35,   0x32,   0x36,    0x65,    0x56,    0x69,    0x78,
    0x30c6,  0x30b7,  0x30b3, 0x30c8, 0x3088,  0x308a,  0x63a,  0x62c,  0x638,   0x645,   0x637,   0x62d,   0x636,
    0x645,   0x636,   0x62c,  0x635,  0x62e,   0x628,   0x645,  0x628,  0x647,   0x64,    0x7a,    0x44,    0x7a,
    0x44,    0x5a,    0x62a,  0x647,  0x62b,   0x645,   0x646,  0x62e,  0x643,   0x644,   0x643,   0x62e,   0x641,
    0x62c,   0x641,   0x62d,  0x642,  0x62d,   0x643,   0x62c,  0x643,  0x62d,   0x6e,    0x6a,    0x4e,    0x6a,
    0x4e,    0x4a,    0x6c,   0x6a,   0x4c,    0x6a,    0x4c,   0x4a,   0x62b,   0x64a,   0x62b,   0x649,   0x62b,
    0x646,   0x62b,   0x632,  0x62b,  0x631,   0x62a,   0x64a,  0x62a,  0x649,   0x62a,   0x646,   0x62a,   0x632,
    0x62a,   0x631,   0x628,  0x64a,  0x628,   0x649,   0x628,  0x646,  0x647,   0x649,   0x647,   0x64a,   0x64a,
    0x62e,   0x64a,   0x649,  0x64a,  0x631,   0x64a,   0x632,  0x628,  0x632,   0x646,   0x646,   0x646,   0x649,
    0x646,   0x64a,   0x628,  0x62c,  0x641,   0x649,   0x641,  0x64a,  0x642,   0x649,   0x642,   0x64a,   0x643,
    0x627,   0x643,   0x649,  0x643,  0x64a,   0x645,   0x627,  0x646,  0x631,   0x646,   0x632,   0x633,   0x631,
    0x634,   0x631,   0x634,  0x62e,  0x636,   0x64a,   0x636,  0x649,  0x635,   0x64a,   0x635,   0x649,   0x57,
    0x5a,    0x43,    0x44,   0x39,   0x2c,    0x633,   0x649,  0x633,  0x64a,   0x634,   0x649,   0x634,   0x64a,
    0x30,    0x2c,    0x31,   0x2c,   0x32,    0x2c,    0x33,   0x2c,   0x34,    0x2c,    0x35,    0x2c,    0x36,
    0x2c,    0x37,    0x2c,   0x38,   0x2c,    0x53,    0x44,   0x53,   0x53,    0x57,    0x43,    0x44,    0x4a,
    0x307b,  0x304b,  0x30b3, 0x30b3, 0x3014,  0x3015,  0x3014, 0x3015, 0x635,   0x631,   0x636,   0x631,   0x633,
    0x647,   0x634,   0x647,  0x48,   0x56,    0x63a,   0x649,  0x639,  0x64a,   0x639,   0x649,   0x637,   0x64a,
    0x637,   0x649,   0x647,  0x62c,  0x62b,   0x647,   0x69,   0x6a,   0x49,    0x4a,    0x63a,   0x64a,   0x2bc,
    0x6e,    0x6c,    0xb7,   0x4c,   0xb7,    0x62e,   0x62d,  0x62b,  0x62c,   0x64a,   0x674,   0x64a,   0x6d0,
    0x64a,   0x6d0,   0x64a,  0x6c8,  0x64a,   0x6c8,   0x64a,  0x6c6,  0x64a,   0x6c6,   0x64a,   0x6c7,   0x64a,
    0x6c7,   0x64a,   0x648,  0x64a,  0x648,   0x64a,   0x6d5,  0x64a,  0x6d5,   0x64a,   0x627,   0x64a,   0x627,
    0xeab,   0xe99,   0xeab,  0xea1,  0x6c7,   0x674,   0x5d0,  0x5dc,  0x73,    0x74,    0x73,    0x74,    0x574,
    0x576,   0x574,   0x565,  0x574,  0x56b,   0x57e,   0x576,  0x574,  0x56d,   0x565,   0x582,   0x627,   0x674,
    0x648,   0x674,   0x50,   0x48,   0x50,    0x52,    0x73,   0x72,   0x57,    0x62,    0x53,    0x76,    0x5c,
    0x5e,    0x5b,    0x5d,   0x30f2, 0x30a5,  0x30e3,  0x60,   0x7b,   0x5f,    0x2013,  0x2014,  0x40,    0x3b,
    0x3001,  0x7d,    0x23,   0x26,   0x2a,    0x2b,    0x2d,   0x3c,   0x3e,    0x7c,    0x30fb,  0x300f,  0x300e,
    0x300d,  0x300c,  0x3009, 0x3008, 0x300b,  0x300a,  0x3011, 0x3010, 0x7e,    0x2985,  0x2986,  0x3002,  0x640,
    0x640,   0x621,   0x630,  0x630,  0x629,   0x629,   0x25,   0x27,   0x3017,  0x3016,  0x24,    0x24,    0x22,
    0x39e,   0x39d,   0x39c,  0x39b,  0x39a,   0x399,   0x398,  0x397,  0x396,   0x395,   0x394,   0x393,   0x392,
    0x391,   0x237,   0x131,  0x3c0,  0x3c1,   0x3c6,   0x3ba,  0x3b8,  0x3b5,   0x2202,  0x3c9,   0x3b2,   0x3b1,
    0x2207,  0x3a8,   0x3a7,  0x3a6,  0x3a5,   0x3a4,   0x3a3,  0x3a1,  0x3a0,   0x39f,   0x3b6,   0x3b4,   0x3b3,
    0x3c8,   0x3c7,   0x3c5,  0x3c4,  0x3c3,   0x3c2,   0x3bf,  0x3be,  0x3bd,   0x3bb,   0x3b9,   0x3b7,   0x3dd,
    0x3dc,   0x11b3,  0x11b2, 0x11b1, 0x11b0,  0x1104,  0x11ad, 0x11ac, 0x11aa,  0x1101,  0x1160,  0x110d,  0x110a,
    0x1121,  0x1108,  0x111a, 0x11b5, 0x11b4,  0x30cc,  0x30e8, 0x30e2, 0x1d1ba, 0x1d1b9, 0x1d1b9, 0x1d158, 0x1d158,
    0x1d157, 0x110a5, 0x1173, 0x1172, 0x1171,  0x1170,  0x116f, 0x116d, 0x116c,  0x116b,  0x116a,  0x1168,  0x1167,
    0x1166,  0x1164,  0x1163, 0x1162, 0x1109b, 0x11099, 0x25cb, 0x25a0, 0x2193,  0x2192,  0x2191,  0x2190,  0x2502,
    0x20a9,  0xa5,    0xa6,   0xac,   0xa3,    0xa2,    0x1175, 0x292,  0x250,   0x251,   0x1d02,  0x259,   0x25b,
    0x25c,   0x14b,   0x254,  0x1d16, 0x1d17,  0x1d1d,  0x26f,  0x1025, 0x10dc,  0x1b05,  0x1b07,  0x1b09,  0x1b0b,
    0x1b0d,  0x1b11,  0xc6,   0x18e,  0x222,   0x268,   0x269,  0x26a,  0x1d7b,  0x29d,   0x26d,   0x1d85,  0x29f,
    0x271,   0x270,   0x272,  0x273,  0x274,   0x275,   0x278,  0x282,  0x283,   0x1ab,   0x289,   0x28a,   0x1d1c,
    0x28b,   0x28c,   0x290,  0x291,  0x1d25,  0x43d,   0x252,  0x255,  0xf0,    0x25f,   0x261,   0x265,   0xe6,
    0x438,   0x443,   0x474,  0x475,  0x416,   0x436,   0x410,  0x430,  0x430,   0x415,   0x435,   0x4d8,   0x4d9,
    0x417,   0x437,   0x418,  0x418,  0x41e,   0x43e,   0x4e8,  0x4e9,  0x413,   0x406,   0x41a,   0x423,   0x433,
    0x456,   0x43a,   0x91c,  0x921,  0x922,   0x92b,   0x92f,  0x9a1,  0x9a2,   0x9af,   0xa32,   0xa38,   0xa16,
    0xa17,   0xa1c,   0xa2b,  0xb21,  0xb22,   0xb92,   0xe32,  0xeb2,  0xf0b,   0xf42,   0xf4c,   0xf51,   0xf56,
    0xf5b,   0xf40,   0x42d,  0x44d,  0x427,   0x447,   0x42b,  0x44b,  0x6c1,   0x928,   0x930,   0x933,   0x915,
    0x916,   0x917,   0x1b7,  0xd8,   0xf8,    0x266,   0x279,  0x27b,  0x281,   0x263,   0x295,   0x2b9,   0x1158,
    0x1159,  0x1184,  0x1185, 0x1188, 0x1191,  0x1192,  0x1194, 0x119e, 0x11a1,  0x11d3,  0x11d7,  0x11d9,  0x111c,
    0x11dd,  0x11df,  0x111d, 0x111e, 0x1120,  0x1122,  0x1123, 0x1127, 0x1129,  0x112b,  0x112c,  0x112d,  0x112e,
    0x112f,  0x1132,  0x1136, 0x1140, 0x1147,  0x114c,  0x11f1, 0x11f2, 0x1157,  0x30f0,  0x30f1,  0x30fd,  0x3068,
    0x306f,  0x306f,  0x3072, 0x3072, 0x3075,  0x3075,  0x3078, 0x3078, 0x3046,  0x309d,  0x1114,  0x1115,  0x11c7,
    0x11c8,  0x11cc,  0x11ce, 0x691,  0x6a9,   0x6a9,   0x6af,  0x6af,  0x6b3,   0x6b3,   0x6b1,   0x6b1,   0x6ba,
    0x6ba,   0x6bb,   0x6bb,  0x684,  0x684,   0x683,   0x683,  0x686,  0x686,   0x687,   0x687,   0x68d,   0x68d,
    0x68c,   0x68c,   0x68e,  0x68e,  0x688,   0x688,   0x698,  0x698,  0x6c9,   0x6be,   0x6be,   0x6ad,   0x6ad,
    0x6cb,   0x6cb,   0x6c5,  0x6c5,  0x5f2,   0x5e2,   0x5d3,  0x5d4,  0x5db,   0x5dd,   0x5e8,   0x5ea,   0x5e9,
    0x5e9,   0x5d1,   0x5d2,  0x5d5,  0x5d6,   0x5d8,   0x5d9,  0xa76f, 0x67e,   0x680,   0x680,   0x67a,   0x67a,
    0x67f,   0x67f,   0x679,  0x679,  0x6a4,   0x6a4,   0x6a6,  0x6a6,  0x5da,   0x5de,   0x5e0,   0x5e1,   0x5e3,
    0x5e4,   0x5e6,   0x5e7,  0x671,  0x671,   0x67b,   0x67b,  0x2212, 0x2010,  0x2277,  0x227a,  0x227b,  0x2282,
    0x2283,  0x2286,  0x2287, 0x22a2, 0x22a8,  0x22a9,  0x22ab, 0x227c, 0x227d,  0x2291,  0x2292,  0x22b2,  0x22b3,
    0x22b4,  0x22b5,  0x2add, 0x2d61, 0x3012,  0x304d,  0x304f, 0x3051, 0x3053,  0x3055,  0x3057,  0x3059,  0x305b,
    0x305d,  0x305f,  0x3061, 0x3064, 0x3066,  0x127,   0x190,  0x2194, 0x21d0,  0x21d4,  0x21d2,  0x2203,  0x2208,
    0x220b,  0x2223,  0x2225, 0x223c, 0x2243,  0x2245,  0x2248, 0x2261, 0x224d,  0x2264,  0x2265,  0x2272,  0x2273,
    0x2276,  0x2211};

static void w(UniString & r, uint16_t startIndex, int count)
{
  for (int i = 0; i < count; ++i)
    r.push_back(normSymbols[startIndex + i]);
}

void NormalizeInplace(UniString & s)
{
  size_t const size = s.size();

  UniString r;
  r.reserve(size);
  for (size_t i = 0; i < size; ++i)
  {
    UniChar const c = s[i];
    // ASCII optimization
    if (c < 0xa0)
      r.push_back(c);
    else
    {
      switch (c & 0xffff0000)
      {
      case 0x0000:
      {
        switch (static_cast<uint16_t>(c & 0x0000ff00))
        {
        case 0x0:
        {
          switch (static_cast<uint8_t>(c & 0xff))
          {
          case 0xa0: w(r, 3, 1); break;
          case 0xa8: w(r, 3, 1); break;
          case 0xaa: w(r, 40, 1); break;
          case 0xaf: w(r, 3, 1); break;
          case 0xb2: w(r, 44, 1); break;
          case 0xb3: w(r, 184, 1); break;
          case 0xb4: w(r, 3, 1); break;
          case 0xb5: w(r, 1244, 1); break;
          case 0xb8: w(r, 3, 1); break;
          case 0xb9: w(r, 158, 1); break;
          case 0xba: w(r, 480, 1); break;
          case 0xbc: w(r, 1085, 3); break;
          case 0xbd: w(r, 1082, 3); break;
          case 0xbe: w(r, 1079, 3); break;
          case 0xc0: w(r, 491, 1); break;
          case 0xc1: w(r, 491, 1); break;
          case 0xc2: w(r, 491, 1); break;
          case 0xc3: w(r, 491, 1); break;
          case 0xc4: w(r, 491, 1); break;
          case 0xc5: w(r, 491, 1); break;
          case 0xc7: w(r, 358, 1); break;
          case 0xc8: w(r, 921, 1); break;
          case 0xc9: w(r, 921, 1); break;
          case 0xca: w(r, 921, 1); break;
          case 0xcb: w(r, 921, 1); break;
          case 0xcc: w(r, 163, 1); break;
          case 0xcd: w(r, 163, 1); break;
          case 0xce: w(r, 163, 1); break;
          case 0xcf: w(r, 163, 1); break;
          case 0xd1: w(r, 1122, 1); break;
          case 0xd2: w(r, 1125, 1); break;
          case 0xd3: w(r, 1125, 1); break;
          case 0xd4: w(r, 1125, 1); break;
          case 0xd5: w(r, 1125, 1); break;
          case 0xd6: w(r, 1125, 1); break;
          case 0xd9: w(r, 1143, 1); break;
          case 0xda: w(r, 1143, 1); break;
          case 0xdb: w(r, 1143, 1); break;
          case 0xdc: w(r, 1143, 1); break;
          case 0xdd: w(r, 1155, 1); break;
          case 0xe0: w(r, 40, 1); break;
          case 0xe1: w(r, 40, 1); break;
          case 0xe2: w(r, 40, 1); break;
          case 0xe3: w(r, 40, 1); break;
          case 0xe4: w(r, 40, 1); break;
          case 0xe5: w(r, 40, 1); break;
          case 0xe7: w(r, 331, 1); break;
          case 0xe8: w(r, 518, 1); break;
          case 0xe9: w(r, 518, 1); break;
          case 0xea: w(r, 518, 1); break;
          case 0xeb: w(r, 518, 1); break;
          case 0xec: w(r, 167, 1); break;
          case 0xed: w(r, 167, 1); break;
          case 0xee: w(r, 167, 1); break;
          case 0xef: w(r, 167, 1); break;
          case 0xf1: w(r, 1059, 1); break;
          case 0xf2: w(r, 480, 1); break;
          case 0xf3: w(r, 480, 1); break;
          case 0xf4: w(r, 480, 1); break;
          case 0xf5: w(r, 480, 1); break;
          case 0xf6: w(r, 480, 1); break;
          case 0xf9: w(r, 967, 1); break;
          case 0xfa: w(r, 967, 1); break;
          case 0xfb: w(r, 967, 1); break;
          case 0xfc: w(r, 967, 1); break;
          case 0xfd: w(r, 1104, 1); break;
          case 0xff: w(r, 1104, 1); break;
          default: r.push_back(c);
          }
        }
        break;
        case 0x100:
        {
          switch (static_cast<uint8_t>(c & 0xff))
          {
          case 0x0: w(r, 491, 1); break;
          case 0x1: w(r, 40, 1); break;
          case 0x2: w(r, 491, 1); break;
          case 0x3: w(r, 40, 1); break;
          case 0x4: w(r, 491, 1); break;
          case 0x5: w(r, 40, 1); break;
          case 0x6: w(r, 358, 1); break;
          case 0x7: w(r, 331, 1); break;
          case 0x8: w(r, 358, 1); break;
          case 0x9: w(r, 331, 1); break;
          case 0xa: w(r, 358, 1); break;
          case 0xb: w(r, 331, 1); break;
          case 0xc: w(r, 358, 1); break;
          case 0xd: w(r, 331, 1); break;
          case 0xe: w(r, 517, 1); break;
          case 0xf: w(r, 41, 1); break;
          case 0x12: w(r, 921, 1); break;
          case 0x13: w(r, 518, 1); break;
          case 0x14: w(r, 921, 1); break;
          case 0x15: w(r, 518, 1); break;
          case 0x16: w(r, 921, 1); break;
          case 0x17: w(r, 518, 1); break;
          case 0x18: w(r, 921, 1); break;
          case 0x19: w(r, 518, 1); break;
          case 0x1a: w(r, 921, 1); break;
          case 0x1b: w(r, 518, 1); break;
          case 0x1c: w(r, 404, 1); break;
          case 0x1d: w(r, 361, 1); break;
          case 0x1e: w(r, 404, 1); break;
          case 0x1f: w(r, 361, 1); break;
          case 0x20: w(r, 404, 1); break;
          case 0x21: w(r, 361, 1); break;
          case 0x22: w(r, 404, 1); break;
          case 0x23: w(r, 361, 1); break;
          case 0x24: w(r, 399, 1); break;
          case 0x25: w(r, 380, 1); break;
          case 0x28: w(r, 163, 1); break;
          case 0x29: w(r, 167, 1); break;
          case 0x2a: w(r, 163, 1); break;
          case 0x2b: w(r, 167, 1); break;
          case 0x2c: w(r, 163, 1); break;
          case 0x2d: w(r, 167, 1); break;
          case 0x2e: w(r, 163, 1); break;
          case 0x2f: w(r, 167, 1); break;
          case 0x30: w(r, 163, 1); break;
          case 0x32: w(r, 1672, 2); break;
          case 0x33: w(r, 1670, 2); break;
          case 0x34: w(r, 936, 1); break;
          case 0x35: w(r, 1047, 1); break;
          case 0x36: w(r, 939, 1); break;
          case 0x37: w(r, 330, 1); break;
          case 0x39: w(r, 515, 1); break;
          case 0x3a: w(r, 333, 1); break;
          case 0x3b: w(r, 515, 1); break;
          case 0x3c: w(r, 333, 1); break;
          case 0x3d: w(r, 515, 1); break;
          case 0x3e: w(r, 333, 1); break;
          case 0x3f: w(r, 1680, 2); break;
          case 0x40: w(r, 1678, 2); break;
          // @HACK Special case for Polish Ł
          case 0x41: w(r, 515, 1); break;
          // @HACK Special case for Polish ł
          case 0x42: w(r, 333, 1); break;
          case 0x43: w(r, 1122, 1); break;
          case 0x44: w(r, 1059, 1); break;
          case 0x45: w(r, 1122, 1); break;
          case 0x46: w(r, 1059, 1); break;
          case 0x47: w(r, 1122, 1); break;
          case 0x48: w(r, 1059, 1); break;
          case 0x49: w(r, 1676, 2); break;
          case 0x4c: w(r, 1125, 1); break;
          case 0x4d: w(r, 480, 1); break;
          case 0x4e: w(r, 1125, 1); break;
          case 0x4f: w(r, 480, 1); break;
          case 0x50: w(r, 1125, 1); break;
          case 0x51: w(r, 480, 1); break;
          case 0x54: w(r, 1134, 1); break;
          case 0x55: w(r, 39, 1); break;
          case 0x56: w(r, 1134, 1); break;
          case 0x57: w(r, 39, 1); break;
          case 0x58: w(r, 1134, 1); break;
          case 0x59: w(r, 39, 1); break;
          case 0x5a: w(r, 1137, 1); break;
          case 0x5b: w(r, 43, 1); break;
          case 0x5c: w(r, 1137, 1); break;
          case 0x5d: w(r, 43, 1); break;
          case 0x5e: w(r, 1137, 1); break;
          case 0x5f: w(r, 43, 1); break;
          case 0x60: w(r, 1137, 1); break;
          case 0x61: w(r, 43, 1); break;
          case 0x62: w(r, 407, 1); break;
          case 0x63: w(r, 1089, 1); break;
          case 0x64: w(r, 407, 1); break;
          case 0x65: w(r, 1089, 1); break;
          case 0x68: w(r, 1143, 1); break;
          case 0x69: w(r, 967, 1); break;
          case 0x6a: w(r, 1143, 1); break;
          case 0x6b: w(r, 967, 1); break;
          case 0x6c: w(r, 1143, 1); break;
          case 0x6d: w(r, 967, 1); break;
          case 0x6e: w(r, 1143, 1); break;
          case 0x6f: w(r, 967, 1); break;
          case 0x70: w(r, 1143, 1); break;
          case 0x71: w(r, 967, 1); break;
          case 0x72: w(r, 1143, 1); break;
          case 0x73: w(r, 967, 1); break;
          case 0x74: w(r, 1149, 1); break;
          case 0x75: w(r, 1098, 1); break;
          case 0x76: w(r, 1155, 1); break;
          case 0x77: w(r, 1104, 1); break;
          case 0x78: w(r, 1155, 1); break;
          case 0x79: w(r, 1158, 1); break;
          case 0x7a: w(r, 400, 1); break;
          case 0x7b: w(r, 1158, 1); break;
          case 0x7c: w(r, 400, 1); break;
          case 0x7d: w(r, 1158, 1); break;
          case 0x7e: w(r, 400, 1); break;
          case 0x7f: w(r, 43, 1); break;
          case 0xa0: w(r, 1125, 1); break;
          case 0xa1: w(r, 480, 1); break;
          case 0xaf: w(r, 1143, 1); break;
          case 0xb0: w(r, 967, 1); break;
          case 0xc4: w(r, 1482, 2); break;
          case 0xc5: w(r, 1480, 2); break;
          case 0xc6: w(r, 1478, 2); break;
          case 0xc7: w(r, 1514, 2); break;
          case 0xc8: w(r, 1512, 2); break;
          case 0xc9: w(r, 1510, 2); break;
          case 0xca: w(r, 1508, 2); break;
          case 0xcb: w(r, 1506, 2); break;
          case 0xcc: w(r, 1504, 2); break;
          case 0xcd: w(r, 491, 1); break;
          case 0xce: w(r, 40, 1); break;
          case 0xcf: w(r, 163, 1); break;
          case 0xd0: w(r, 167, 1); break;
          case 0xd1: w(r, 1125, 1); break;
          case 0xd2: w(r, 480, 1); break;
          case 0xd3: w(r, 1143, 1); break;
          case 0xd4: w(r, 967, 1); break;
          case 0xd5: w(r, 1143, 1); break;
          case 0xd6: w(r, 967, 1); break;
          case 0xd7: w(r, 1143, 1); break;
          case 0xd8: w(r, 967, 1); break;
          case 0xd9: w(r, 1143, 1); break;
          case 0xda: w(r, 967, 1); break;
          case 0xdb: w(r, 1143, 1); break;
          case 0xdc: w(r, 967, 1); break;
          case 0xde: w(r, 491, 1); break;
          case 0xdf: w(r, 40, 1); break;
          case 0xe0: w(r, 491, 1); break;
          case 0xe1: w(r, 40, 1); break;
          case 0xe2: w(r, 1939, 1); break;
          case 0xe3: w(r, 1975, 1); break;
          case 0xe6: w(r, 404, 1); break;
          case 0xe7: w(r, 361, 1); break;
          case 0xe8: w(r, 939, 1); break;
          case 0xe9: w(r, 330, 1); break;
          case 0xea: w(r, 1125, 1); break;
          case 0xeb: w(r, 480, 1); break;
          case 0xec: w(r, 1125, 1); break;
          case 0xed: w(r, 480, 1); break;
          case 0xee: w(r, 2043, 1); break;
          case 0xef: w(r, 1918, 1); break;
          case 0xf0: w(r, 1047, 1); break;
          case 0xf1: w(r, 1482, 2); break;
          case 0xf2: w(r, 1480, 2); break;
          case 0xf3: w(r, 1478, 2); break;
          case 0xf4: w(r, 404, 1); break;
          case 0xf5: w(r, 361, 1); break;
          case 0xf8: w(r, 1122, 1); break;
          case 0xf9: w(r, 1059, 1); break;
          case 0xfa: w(r, 491, 1); break;
          case 0xfb: w(r, 40, 1); break;
          case 0xfc: w(r, 1939, 1); break;
          case 0xfd: w(r, 1975, 1); break;
          case 0xfe: w(r, 2044, 1); break;
          case 0xff: w(r, 2045, 1); break;
          default: r.push_back(c);
          }
        }
        break;
        case 0x200:
        {
          switch (static_cast<uint8_t>(c & 0xff))
          {
          case 0x0: w(r, 491, 1); break;
          case 0x1: w(r, 40, 1); break;
          case 0x2: w(r, 491, 1); break;
          case 0x3: w(r, 40, 1); break;
          case 0x4: w(r, 921, 1); break;
          case 0x5: w(r, 518, 1); break;
          case 0x6: w(r, 921, 1); break;
          case 0x7: w(r, 518, 1); break;
          case 0x8: w(r, 163, 1); break;
          case 0x9: w(r, 167, 1); break;
          case 0xa: w(r, 163, 1); break;
          case 0xb: w(r, 167, 1); break;
          case 0xc: w(r, 1125, 1); break;
          case 0xd: w(r, 480, 1); break;
          case 0xe: w(r, 1125, 1); break;
          case 0xf: w(r, 480, 1); break;
          case 0x10: w(r, 1134, 1); break;
          case 0x11: w(r, 39, 1); break;
          case 0x12: w(r, 1134, 1); break;
          case 0x13: w(r, 39, 1); break;
          case 0x14: w(r, 1143, 1); break;
          case 0x15: w(r, 967, 1); break;
          case 0x16: w(r, 1143, 1); break;
          case 0x17: w(r, 967, 1); break;
          case 0x18: w(r, 1137, 1); break;
          case 0x19: w(r, 43, 1); break;
          case 0x1a: w(r, 407, 1); break;
          case 0x1b: w(r, 1089, 1); break;
          case 0x1e: w(r, 399, 1); break;
          case 0x1f: w(r, 380, 1); break;
          case 0x26: w(r, 491, 1); break;
          case 0x27: w(r, 40, 1); break;
          case 0x28: w(r, 921, 1); break;
          case 0x29: w(r, 518, 1); break;
          case 0x2a: w(r, 1125, 1); break;
          case 0x2b: w(r, 480, 1); break;
          case 0x2c: w(r, 1125, 1); break;
          case 0x2d: w(r, 480, 1); break;
          case 0x2e: w(r, 1125, 1); break;
          case 0x2f: w(r, 480, 1); break;
          case 0x30: w(r, 1125, 1); break;
          case 0x31: w(r, 480, 1); break;
          case 0x32: w(r, 1155, 1); break;
          case 0x33: w(r, 1104, 1); break;
          case 0xb0: w(r, 380, 1); break;
          case 0xb1: w(r, 2046, 1); break;
          case 0xb2: w(r, 1047, 1); break;
          case 0xb3: w(r, 39, 1); break;
          case 0xb4: w(r, 2047, 1); break;
          case 0xb5: w(r, 2048, 1); break;
          case 0xb6: w(r, 2049, 1); break;
          case 0xb7: w(r, 1098, 1); break;
          case 0xb8: w(r, 1104, 1); break;
          case 0xd8: w(r, 3, 1); break;
          case 0xd9: w(r, 3, 1); break;
          case 0xda: w(r, 3, 1); break;
          case 0xdb: w(r, 3, 1); break;
          case 0xdc: w(r, 3, 1); break;
          case 0xdd: w(r, 3, 1); break;
          case 0xe0: w(r, 2050, 1); break;
          case 0xe1: w(r, 333, 1); break;
          case 0xe2: w(r, 43, 1); break;
          case 0xe3: w(r, 872, 1); break;
          case 0xe4: w(r, 2051, 1); break;
          default: r.push_back(c);
          }
        }
        break;
        case 0x300:
        {
          switch (static_cast<uint8_t>(c & 0xff))
          {
          case 0x74: w(r, 2052, 1); break;
          case 0x7a: w(r, 3, 1); break;
          case 0x7e: w(r, 1767, 1); break;
          case 0x84: w(r, 3, 1); break;
          case 0x85: w(r, 3, 1); break;
          case 0x86: w(r, 1820, 1); break;
          case 0x87: w(r, 1679, 1); break;
          case 0x88: w(r, 1816, 1); break;
          case 0x89: w(r, 1814, 1); break;
          case 0x8a: w(r, 1812, 1); break;
          case 0x8c: w(r, 1842, 1); break;
          case 0x8e: w(r, 1837, 1); break;
          case 0x8f: w(r, 1333, 1); break;
          case 0x90: w(r, 1856, 1); break;
          case 0xaa: w(r, 1812, 1); break;
          case 0xab: w(r, 1837, 1); break;
          case 0xac: w(r, 1832, 1); break;
          case 0xad: w(r, 1828, 1); break;
          case 0xae: w(r, 1857, 1); break;
          case 0xaf: w(r, 1856, 1); break;
          case 0xb0: w(r, 1848, 1); break;
          case 0xca: w(r, 1856, 1); break;
          case 0xcb: w(r, 1848, 1); break;
          case 0xcc: w(r, 1852, 1); break;
          case 0xcd: w(r, 1848, 1); break;
          case 0xce: w(r, 1830, 1); break;
          case 0xd0: w(r, 1831, 1); break;
          case 0xd1: w(r, 1827, 1); break;
          case 0xd2: w(r, 1837, 1); break;
          case 0xd3: w(r, 1837, 1); break;
          case 0xd4: w(r, 1837, 1); break;
          case 0xd5: w(r, 1825, 1); break;
          case 0xd6: w(r, 1823, 1); break;
          case 0xf0: w(r, 1826, 1); break;
          case 0xf1: w(r, 1824, 1); break;
          case 0xf2: w(r, 1851, 1); break;
          case 0xf4: w(r, 1813, 1); break;
          case 0xf5: w(r, 1828, 1); break;
          case 0xf9: w(r, 1839, 1); break;
          default: r.push_back(c);
          }
        }
        break;
        case 0x400:
        {
          switch (static_cast<uint8_t>(c & 0xff))
          {
          case 0x0: w(r, 1985, 1); break;
          case 0x1: w(r, 1985, 1); break;
          case 0x3: w(r, 1997, 1); break;
          case 0x7: w(r, 1998, 1); break;
          case 0xc: w(r, 1999, 1); break;
          case 0xd: w(r, 1991, 1); break;
          case 0xe: w(r, 2000, 1); break;
          case 0x19: w(r, 1991, 1); break;
          case 0x39: w(r, 1976, 1); break;
          case 0x50: w(r, 1986, 1); break;
          case 0x51: w(r, 1986, 1); break;
          case 0x53: w(r, 2001, 1); break;
          case 0x57: w(r, 2002, 1); break;
          case 0x5c: w(r, 2003, 1); break;
          case 0x5d: w(r, 1976, 1); break;
          case 0x5e: w(r, 1977, 1); break;
          case 0x76: w(r, 1978, 1); break;
          case 0x77: w(r, 1979, 1); break;
          case 0xc1: w(r, 1980, 1); break;
          case 0xc2: w(r, 1981, 1); break;
          case 0xd0: w(r, 1982, 1); break;
          case 0xd1: w(r, 1983, 1); break;
          case 0xd2: w(r, 1982, 1); break;
          case 0xd3: w(r, 1983, 1); break;
          case 0xd6: w(r, 1985, 1); break;
          case 0xd7: w(r, 1986, 1); break;
          case 0xda: w(r, 1987, 1); break;
          case 0xdb: w(r, 1988, 1); break;
          case 0xdc: w(r, 1980, 1); break;
          case 0xdd: w(r, 1981, 1); break;
          case 0xde: w(r, 1989, 1); break;
          case 0xdf: w(r, 1990, 1); break;
          case 0xe2: w(r, 1991, 1); break;
          case 0xe3: w(r, 1976, 1); break;
          case 0xe4: w(r, 1991, 1); break;
          case 0xe5: w(r, 1976, 1); break;
          case 0xe6: w(r, 1993, 1); break;
          case 0xe7: w(r, 1994, 1); break;
          case 0xea: w(r, 1995, 1); break;
          case 0xeb: w(r, 1996, 1); break;
          case 0xec: w(r, 2030, 1); break;
          case 0xed: w(r, 2031, 1); break;
          case 0xee: w(r, 2000, 1); break;
          case 0xef: w(r, 1977, 1); break;
          case 0xf0: w(r, 2000, 1); break;
          case 0xf1: w(r, 1977, 1); break;
          case 0xf2: w(r, 2000, 1); break;
          case 0xf3: w(r, 1977, 1); break;
          case 0xf4: w(r, 2032, 1); break;
          case 0xf5: w(r, 2033, 1); break;
          case 0xf8: w(r, 2034, 1); break;
          case 0xf9: w(r, 2035, 1); break;
          default: r.push_back(c);
          }
        }
        break;
        case 0x500:
        {
          switch (static_cast<uint8_t>(c & 0xff))
          {
          case 0x87: w(r, 1738, 2); break;
          default: r.push_back(c);
          }
        }
        break;
        case 0x600: /* Arabic Language */
        {
          switch (static_cast<uint8_t>(c & 0xff))
          {
          case 0x0c: w(r, 1603, 1); break;  // ARABIC COMMA
          case 0x22: w(r, 4, 1); break;     // ARABIC LETTER ALEF WITH MADDA ABOVE
          case 0x23: w(r, 4, 1); break;     // ARABIC LETTER ALEF WITH HAMZA ABOVE
          case 0x24: w(r, 14, 1); break;    // ARABIC LETTER WAW WITH HAMZA ABOVE
          case 0x25: w(r, 4, 1); break;     // ARABIC LETTER ALEF WITH HAMZA BELOW
          case 0x26: w(r, 11, 1); break;    // ARABIC LETTER YEH WITH HAMZA ABOVE
          case 0x29: w(r, 7, 1); break;     // ARABIC LETTER TEH MARBUTA
          case 0x49: w(r, 11, 1); break;    // ARABIC LETTER ALEF MAKSURA
          case 0x71: w(r, 4, 1); break;     // ARABIC LETTER ALEF WASLA
          case 0x72: w(r, 4, 1); break;     // ARABIC LETTER ALEF WITH WAVY HAMZA ABOVE
          case 0x73: w(r, 4, 1); break;     // ARABIC LETTER ALEF WITH WAVY HAMZA BELOW
          case 0x75: w(r, 1740, 1); break;  // ARABIC LETTER HIGH HAMZA ALEF
          case 0x76: w(r, 1742, 1); break;  // ARABIC LETTER HIGH HAMZA WAW
          case 0x77: w(r, 1742, 1); break;  // ARABIC LETTER U WITH HAMZA ABOVE
          case 0x78: w(r, 1686, 1); break;  // ARABIC LETTER HIGH HAMZA YEH
          case 0xc0: w(r, 7, 1); break;     // ARABIC LETTER HEH WITH YEH ABOVE
          case 0xc2: w(r, 7, 1); break;     // ARABIC LETTER HEH GOAL WITH HAMZA ABOVE
          case 0xc3: w(r, 7, 1); break;     // ARABIC LETTER TEH MARBUTA GOAL
          case 0xd3:
            w(r, 424, 1);
            break;  // ARABIC LETTER YEH BARREE WITH HAMZA ABOVE

          //  ARABIC-INDIC DIGITS
          case 0x60: w(r, 172, 1); break;  // ARABIC-INDIC DIGIT ZERO
          case 0x61: w(r, 176, 1); break;  // ARABIC-INDIC DIGIT ONE
          case 0x62: w(r, 180, 1); break;  // ARABIC-INDIC DIGIT TWO
          case 0x63: w(r, 184, 1); break;  // ARABIC-INDIC DIGIT THREE
          case 0x64: w(r, 188, 1); break;  // ARABIC-INDIC DIGIT FOUR
          case 0x65: w(r, 192, 1); break;  // ARABIC-INDIC DIGIT FIVE
          case 0x66: w(r, 196, 1); break;  // ARABIC-INDIC DIGIT SIX
          case 0x67: w(r, 200, 1); break;  // ARABIC-INDIC DIGIT SEVEN
          case 0x68: w(r, 204, 1); break;  // ARABIC-INDIC DIGIT EIGHT
          case 0x69:
            w(r, 208, 1);
            break;  // ARABIC-INDIC DIGIT NINE

          // EXTENDED ARABIC-INDIC DIGITS
          case 0xf0: w(r, 172, 1); break;  // EXTENDED ARABIC-INDIC DIGIT ZERO
          case 0xf1: w(r, 176, 1); break;  // EXTENDED ARABIC-INDIC DIGIT ONE
          case 0xf2: w(r, 180, 1); break;  // EXTENDED ARABIC-INDIC DIGIT TWO
          case 0xf3: w(r, 184, 1); break;  // EXTENDED ARABIC-INDIC DIGIT THREE
          case 0xf4: w(r, 188, 1); break;  // EXTENDED ARABIC-INDIC DIGIT FOUR
          case 0xf5: w(r, 192, 1); break;  // EXTENDED ARABIC-INDIC DIGIT FIVE
          case 0xf6: w(r, 196, 1); break;  // EXTENDED ARABIC-INDIC DIGIT SIX
          case 0xf7: w(r, 200, 1); break;  // EXTENDED ARABIC-INDIC DIGIT SEVEN
          case 0xf8: w(r, 204, 1); break;  // EXTENDED ARABIC-INDIC DIGIT EIGHT
          case 0xf9:
            w(r, 208, 1);
            break;  // EXTENDED ARABIC-INDIC DIGIT NINE

          // Remove Arabic Diacritics (Tashkeel)
          case 0x40: break;  // ARABIC TATWEEL
          case 0x4b: break;  // ARABIC FATHATAN
          case 0x4c: break;  // ARABIC DAMMATAN
          case 0x4d: break;  // ARABIC KASRATAN
          case 0x4e: break;  // ARABIC FATHA
          case 0x4f: break;  // ARABIC DAMMA
          case 0x50: break;  // ARABIC KASRA
          case 0x51: break;  // ARABIC SHADDA
          case 0x52: break;  // ARABIC SUKUN
          case 0x53: break;  // ARABIC MADDAH ABOVE
          case 0x54: break;  // ARABIC HAMZA ABOVE
          case 0x55: break;  // ARABIC HAMZA BELOW
          case 0x56: break;  // ARABIC SUBSCRIPT ALEF
          case 0x57: break;  // ARABIC INVERTED DAMMA
          case 0x58: break;  // ARABIC MARK NOON GHUNNA
          case 0x59: break;  // ARABIC ZWARAKAY
          case 0x5a: break;  // ARABIC VOWEL SIGN SMALL V ABOVE
          case 0x5b: break;  // ARABIC VOWEL SIGN INVERTED SMALL V ABOVE
          case 0x5c: break;  // ARABIC VOWEL SIGN DOT BELOW
          case 0x5d: break;  // ARABIC REVERSED DAMMA
          case 0x5e: break;  // ARABIC FATHA WITH TWO DOTS
          case 0x5f: break;  // ARABIC WAVY HAMZA BELOW
          case 0x70:
            break;  // ARABIC LETTER SUPERSCRIPT ALEF

          // Remove Arabic Islamic Honorifics
          case 0x10: break;  // ARABIC SIGN SALLALLAHOU ALAYHE WASSALLAM
          case 0x11: break;  // ARABIC SIGN ALAYHE ASSALLAM
          case 0x12: break;  // ARABIC SIGN RAHMATULLAH ALAYHE
          case 0x13: break;  // ARABIC SIGN RADI ALLAHU ANHU
          case 0x14: break;  // ARABIC SIGN TAKHALLUS
          case 0x15: break;  // ARABIC SMALL HIGH TAH
          case 0x16: break;  // ARABIC SMALL HIGH LIGATURE ALEF WITH LAM WITH YEH
          case 0x17: break;  // ARABIC SMALL HIGH ZAIN
          case 0x18: break;  // ARABIC SMALL FATHA
          case 0x19: break;  // ARABIC SMALL DAMMA
          case 0x1a:
            break;  // ARABIC SMALL KASRA

          // Remove Arabic Quranic Annotations
          case 0xd6: break;  // ARABIC SMALL HIGH LIGATURE SAD WITH LAM WITH ALEF MAKSURA
          case 0xd7: break;  // ARABIC SMALL HIGH LIGATURE QAF WITH LAM WITH ALEF MAKSURA
          case 0xd8: break;  // ARABIC SMALL HIGH MEEM INITIAL FORM
          case 0xd9: break;  // ARABIC SMALL HIGH LAM ALEF
          case 0xda: break;  // ARABIC SMALL HIGH JEEM
          case 0xdb: break;  // ARABIC SMALL HIGH THREE DOTS
          case 0xdc: break;  // ARABIC SMALL HIGH SEEN
          case 0xdd: break;  // ARABIC END OF AYAH
          case 0xde: break;  // ARABIC START OF RUB EL HIZB
          case 0xdf: break;  // ARABIC SMALL HIGH ROUNDED ZERO
          case 0xe0: break;  // ARABIC SMALL HIGH UPRIGHT RECTANGULAR ZERO
          case 0xe1: break;  // ARABIC SMALL HIGH DOTLESS HEAD OF KHAH
          case 0xe2: break;  // ARABIC SMALL HIGH MEEM ISOLATED FORM
          case 0xe3: break;  // ARABIC SMALL LOW SEEN
          case 0xe4: break;  // ARABIC SMALL HIGH MADDA
          case 0xe5: break;  // ARABIC SMALL WAW
          case 0xe6: break;  // ARABIC SMALL YEH
          case 0xe7: break;  // ARABIC SMALL HIGH YEH
          case 0xe8: break;  // ARABIC SMALL HIGH NOON
          case 0xe9: break;  // ARABIC PLACE OF SAJDAH
          case 0xea: break;  // ARABIC EMPTY CENTRE LOW STOP
          case 0xeb: break;  // ARABIC EMPTY CENTRE HIGH STOP
          case 0xec: break;  // ARABIC ROUNDED HIGH STOP WITH FILLED CENTRE
          case 0xed: break;  // ARABIC SMALL LOW MEEM

          default: r.push_back(c);
          }
        }
        break;
        case 0x900:
        {
          switch (static_cast<uint8_t>(c & 0xff))
          {
          case 0x29: w(r, 2037, 1); break;
          case 0x31: w(r, 2038, 1); break;
          case 0x34: w(r, 2039, 1); break;
          case 0x58: w(r, 2040, 1); break;
          case 0x59: w(r, 2041, 1); break;
          case 0x5a: w(r, 2042, 1); break;
          case 0x5b: w(r, 2004, 1); break;
          case 0x5c: w(r, 2005, 1); break;
          case 0x5d: w(r, 2006, 1); break;
          case 0x5e: w(r, 2007, 1); break;
          case 0x5f: w(r, 2008, 1); break;
          case 0xdc: w(r, 2009, 1); break;
          case 0xdd: w(r, 2010, 1); break;
          case 0xdf: w(r, 2011, 1); break;
          default: r.push_back(c);
          }
        }
        break;
        case 0xa00:
        {
          switch (static_cast<uint8_t>(c & 0xff))
          {
          case 0x33: w(r, 2012, 1); break;
          case 0x36: w(r, 2013, 1); break;
          case 0x59: w(r, 2014, 1); break;
          case 0x5a: w(r, 2015, 1); break;
          case 0x5b: w(r, 2016, 1); break;
          case 0x5e: w(r, 2017, 1); break;
          default: r.push_back(c);
          }
        }
        break;
        case 0xb00:
        {
          switch (static_cast<uint8_t>(c & 0xff))
          {
          case 0x5c: w(r, 2018, 1); break;
          case 0x5d: w(r, 2019, 1); break;
          case 0x94: w(r, 2020, 1); break;
          default: r.push_back(c);
          }
        }
        break;
        case 0xe00:
        {
          switch (static_cast<uint8_t>(c & 0xff))
          {
          case 0x33: w(r, 2021, 1); break;
          case 0xb3: w(r, 2022, 1); break;
          case 0xdc: w(r, 1716, 2); break;
          case 0xdd: w(r, 1718, 2); break;
          default: r.push_back(c);
          }
        }
        break;
        case 0xf00:
        {
          switch (static_cast<uint8_t>(c & 0xff))
          {
          case 0xc: w(r, 2023, 1); break;
          case 0x43: w(r, 2024, 1); break;
          case 0x4d: w(r, 2025, 1); break;
          case 0x52: w(r, 2026, 1); break;
          case 0x57: w(r, 2027, 1); break;
          case 0x5c: w(r, 2028, 1); break;
          case 0x69: w(r, 2029, 1); break;
          default: r.push_back(c);
          }
        }
        break;
        case 0x1000:
        {
          switch (static_cast<uint8_t>(c & 0xff))
          {
          case 0x26: w(r, 1931, 1); break;
          case 0xfc: w(r, 1932, 1); break;
          default: r.push_back(c);
          }
        }
        break;
        case 0x1b00:
        {
          switch (static_cast<uint8_t>(c & 0xff))
          {
          case 0x6: w(r, 1933, 1); break;
          case 0x8: w(r, 1934, 1); break;
          case 0xa: w(r, 1935, 1); break;
          case 0xc: w(r, 1936, 1); break;
          case 0xe: w(r, 1937, 1); break;
          case 0x12: w(r, 1938, 1); break;
          default: r.push_back(c);
          }
        }
        break;
        case 0x1d00:
        {
          switch (static_cast<uint8_t>(c & 0xff))
          {
          case 0x2c: w(r, 491, 1); break;
          case 0x2d: w(r, 1939, 1); break;
          case 0x2e: w(r, 912, 1); break;
          case 0x30: w(r, 517, 1); break;
          case 0x31: w(r, 921, 1); break;
          case 0x32: w(r, 1940, 1); break;
          case 0x33: w(r, 404, 1); break;
          case 0x34: w(r, 399, 1); break;
          case 0x35: w(r, 163, 1); break;
          case 0x36: w(r, 936, 1); break;
          case 0x37: w(r, 939, 1); break;
          case 0x38: w(r, 515, 1); break;
          case 0x39: w(r, 401, 1); break;
          case 0x3a: w(r, 1122, 1); break;
          case 0x3c: w(r, 1125, 1); break;
          case 0x3d: w(r, 1941, 1); break;
          case 0x3e: w(r, 381, 1); break;
          case 0x3f: w(r, 1134, 1); break;
          case 0x40: w(r, 407, 1); break;
          case 0x41: w(r, 1143, 1); break;
          case 0x42: w(r, 1149, 1); break;
          case 0x43: w(r, 40, 1); break;
          case 0x44: w(r, 1919, 1); break;
          case 0x45: w(r, 1920, 1); break;
          case 0x46: w(r, 1921, 1); break;
          case 0x47: w(r, 383, 1); break;
          case 0x48: w(r, 41, 1); break;
          case 0x49: w(r, 518, 1); break;
          case 0x4a: w(r, 1922, 1); break;
          case 0x4b: w(r, 1923, 1); break;
          case 0x4c: w(r, 1924, 1); break;
          case 0x4d: w(r, 361, 1); break;
          case 0x4f: w(r, 330, 1); break;
          case 0x50: w(r, 334, 1); break;
          case 0x51: w(r, 1925, 1); break;
          case 0x52: w(r, 480, 1); break;
          case 0x53: w(r, 1926, 1); break;
          case 0x54: w(r, 1927, 1); break;
          case 0x55: w(r, 1928, 1); break;
          case 0x56: w(r, 366, 1); break;
          case 0x57: w(r, 1089, 1); break;
          case 0x58: w(r, 967, 1); break;
          case 0x59: w(r, 1929, 1); break;
          case 0x5a: w(r, 1930, 1); break;
          case 0x5b: w(r, 166, 1); break;
          case 0x5c: w(r, 1967, 1); break;
          case 0x5d: w(r, 1831, 1); break;
          case 0x5e: w(r, 1845, 1); break;
          case 0x5f: w(r, 1844, 1); break;
          case 0x60: w(r, 1825, 1); break;
          case 0x61: w(r, 1847, 1); break;
          case 0x62: w(r, 167, 1); break;
          case 0x63: w(r, 39, 1); break;
          case 0x64: w(r, 967, 1); break;
          case 0x65: w(r, 166, 1); break;
          case 0x66: w(r, 1831, 1); break;
          case 0x67: w(r, 1845, 1); break;
          case 0x68: w(r, 1824, 1); break;
          case 0x69: w(r, 1825, 1); break;
          case 0x6a: w(r, 1847, 1); break;
          case 0x78: w(r, 1968, 1); break;
          case 0x9b: w(r, 1969, 1); break;
          case 0x9c: w(r, 331, 1); break;
          case 0x9d: w(r, 1970, 1); break;
          case 0x9e: w(r, 1971, 1); break;
          case 0x9f: w(r, 1924, 1); break;
          case 0xa0: w(r, 593, 1); break;
          case 0xa1: w(r, 1972, 1); break;
          case 0xa2: w(r, 1973, 1); break;
          case 0xa3: w(r, 1974, 1); break;
          case 0xa4: w(r, 1942, 1); break;
          case 0xa5: w(r, 1943, 1); break;
          case 0xa6: w(r, 1944, 1); break;
          case 0xa7: w(r, 1945, 1); break;
          case 0xa8: w(r, 1946, 1); break;
          case 0xa9: w(r, 1947, 1); break;
          case 0xaa: w(r, 1948, 1); break;
          case 0xab: w(r, 1949, 1); break;
          case 0xac: w(r, 1950, 1); break;
          case 0xad: w(r, 1951, 1); break;
          case 0xae: w(r, 1952, 1); break;
          case 0xaf: w(r, 1953, 1); break;
          case 0xb0: w(r, 1954, 1); break;
          case 0xb1: w(r, 1955, 1); break;
          case 0xb2: w(r, 1956, 1); break;
          case 0xb3: w(r, 1957, 1); break;
          case 0xb4: w(r, 1958, 1); break;
          case 0xb5: w(r, 1959, 1); break;
          case 0xb6: w(r, 1960, 1); break;
          case 0xb7: w(r, 1961, 1); break;
          case 0xb8: w(r, 1962, 1); break;
          case 0xb9: w(r, 1963, 1); break;
          case 0xba: w(r, 1964, 1); break;
          case 0xbb: w(r, 400, 1); break;
          case 0xbc: w(r, 1965, 1); break;
          case 0xbd: w(r, 1966, 1); break;
          case 0xbe: w(r, 1918, 1); break;
          case 0xbf: w(r, 1827, 1); break;
          default: r.push_back(c);
          }
        }
        break;
        case 0x1e00:
        {
          switch (static_cast<uint8_t>(c & 0xff))
          {
          case 0x0: w(r, 491, 1); break;
          case 0x1: w(r, 40, 1); break;
          case 0x2: w(r, 912, 1); break;
          case 0x3: w(r, 383, 1); break;
          case 0x4: w(r, 912, 1); break;
          case 0x5: w(r, 383, 1); break;
          case 0x6: w(r, 912, 1); break;
          case 0x7: w(r, 383, 1); break;
          case 0x8: w(r, 358, 1); break;
          case 0x9: w(r, 331, 1); break;
          case 0xa: w(r, 517, 1); break;
          case 0xb: w(r, 41, 1); break;
          case 0xc: w(r, 517, 1); break;
          case 0xd: w(r, 41, 1); break;
          case 0xe: w(r, 517, 1); break;
          case 0xf: w(r, 41, 1); break;
          case 0x10: w(r, 517, 1); break;
          case 0x11: w(r, 41, 1); break;
          case 0x12: w(r, 517, 1); break;
          case 0x13: w(r, 41, 1); break;
          case 0x14: w(r, 921, 1); break;
          case 0x15: w(r, 518, 1); break;
          case 0x16: w(r, 921, 1); break;
          case 0x17: w(r, 518, 1); break;
          case 0x18: w(r, 921, 1); break;
          case 0x19: w(r, 518, 1); break;
          case 0x1a: w(r, 921, 1); break;
          case 0x1b: w(r, 518, 1); break;
          case 0x1c: w(r, 921, 1); break;
          case 0x1d: w(r, 518, 1); break;
          case 0x1e: w(r, 924, 1); break;
          case 0x1f: w(r, 593, 1); break;
          case 0x20: w(r, 404, 1); break;
          case 0x21: w(r, 361, 1); break;
          case 0x22: w(r, 399, 1); break;
          case 0x23: w(r, 380, 1); break;
          case 0x24: w(r, 399, 1); break;
          case 0x25: w(r, 380, 1); break;
          case 0x26: w(r, 399, 1); break;
          case 0x27: w(r, 380, 1); break;
          case 0x28: w(r, 399, 1); break;
          case 0x29: w(r, 380, 1); break;
          case 0x2a: w(r, 399, 1); break;
          case 0x2b: w(r, 380, 1); break;
          case 0x2c: w(r, 163, 1); break;
          case 0x2d: w(r, 167, 1); break;
          case 0x2e: w(r, 163, 1); break;
          case 0x2f: w(r, 167, 1); break;
          case 0x30: w(r, 939, 1); break;
          case 0x31: w(r, 330, 1); break;
          case 0x32: w(r, 939, 1); break;
          case 0x33: w(r, 330, 1); break;
          case 0x34: w(r, 939, 1); break;
          case 0x35: w(r, 330, 1); break;
          case 0x36: w(r, 515, 1); break;
          case 0x37: w(r, 333, 1); break;
          case 0x38: w(r, 515, 1); break;
          case 0x39: w(r, 333, 1); break;
          case 0x3a: w(r, 515, 1); break;
          case 0x3b: w(r, 333, 1); break;
          case 0x3c: w(r, 515, 1); break;
          case 0x3d: w(r, 333, 1); break;
          case 0x3e: w(r, 401, 1); break;
          case 0x3f: w(r, 334, 1); break;
          case 0x40: w(r, 401, 1); break;
          case 0x41: w(r, 334, 1); break;
          case 0x42: w(r, 401, 1); break;
          case 0x43: w(r, 334, 1); break;
          case 0x44: w(r, 1122, 1); break;
          case 0x45: w(r, 1059, 1); break;
          case 0x46: w(r, 1122, 1); break;
          case 0x47: w(r, 1059, 1); break;
          case 0x48: w(r, 1122, 1); break;
          case 0x49: w(r, 1059, 1); break;
          case 0x4a: w(r, 1122, 1); break;
          case 0x4b: w(r, 1059, 1); break;
          case 0x4c: w(r, 1125, 1); break;
          case 0x4d: w(r, 480, 1); break;
          case 0x4e: w(r, 1125, 1); break;
          case 0x4f: w(r, 480, 1); break;
          case 0x50: w(r, 1125, 1); break;
          case 0x51: w(r, 480, 1); break;
          case 0x52: w(r, 1125, 1); break;
          case 0x53: w(r, 480, 1); break;
          case 0x54: w(r, 381, 1); break;
          case 0x55: w(r, 366, 1); break;
          case 0x56: w(r, 381, 1); break;
          case 0x57: w(r, 366, 1); break;
          case 0x58: w(r, 1134, 1); break;
          case 0x59: w(r, 39, 1); break;
          case 0x5a: w(r, 1134, 1); break;
          case 0x5b: w(r, 39, 1); break;
          case 0x5c: w(r, 1134, 1); break;
          case 0x5d: w(r, 39, 1); break;
          case 0x5e: w(r, 1134, 1); break;
          case 0x5f: w(r, 39, 1); break;
          case 0x60: w(r, 1137, 1); break;
          case 0x61: w(r, 43, 1); break;
          case 0x62: w(r, 1137, 1); break;
          case 0x63: w(r, 43, 1); break;
          case 0x64: w(r, 1137, 1); break;
          case 0x65: w(r, 43, 1); break;
          case 0x66: w(r, 1137, 1); break;
          case 0x67: w(r, 43, 1); break;
          case 0x68: w(r, 1137, 1); break;
          case 0x69: w(r, 43, 1); break;
          case 0x6a: w(r, 407, 1); break;
          case 0x6b: w(r, 1089, 1); break;
          case 0x6c: w(r, 407, 1); break;
          case 0x6d: w(r, 1089, 1); break;
          case 0x6e: w(r, 407, 1); break;
          case 0x6f: w(r, 1089, 1); break;
          case 0x70: w(r, 407, 1); break;
          case 0x71: w(r, 1089, 1); break;
          case 0x72: w(r, 1143, 1); break;
          case 0x73: w(r, 967, 1); break;
          case 0x74: w(r, 1143, 1); break;
          case 0x75: w(r, 967, 1); break;
          case 0x76: w(r, 1143, 1); break;
          case 0x77: w(r, 967, 1); break;
          case 0x78: w(r, 1143, 1); break;
          case 0x79: w(r, 967, 1); break;
          case 0x7a: w(r, 1143, 1); break;
          case 0x7b: w(r, 967, 1); break;
          case 0x7c: w(r, 162, 1); break;
          case 0x7d: w(r, 166, 1); break;
          case 0x7e: w(r, 162, 1); break;
          case 0x7f: w(r, 166, 1); break;
          case 0x80: w(r, 1149, 1); break;
          case 0x81: w(r, 1098, 1); break;
          case 0x82: w(r, 1149, 1); break;
          case 0x83: w(r, 1098, 1); break;
          case 0x84: w(r, 1149, 1); break;
          case 0x85: w(r, 1098, 1); break;
          case 0x86: w(r, 1149, 1); break;
          case 0x87: w(r, 1098, 1); break;
          case 0x88: w(r, 1149, 1); break;
          case 0x89: w(r, 1098, 1); break;
          case 0x8a: w(r, 869, 1); break;
          case 0x8b: w(r, 872, 1); break;
          case 0x8c: w(r, 869, 1); break;
          case 0x8d: w(r, 872, 1); break;
          case 0x8e: w(r, 1155, 1); break;
          case 0x8f: w(r, 1104, 1); break;
          case 0x90: w(r, 1158, 1); break;
          case 0x91: w(r, 400, 1); break;
          case 0x92: w(r, 1158, 1); break;
          case 0x93: w(r, 400, 1); break;
          case 0x94: w(r, 1158, 1); break;
          case 0x95: w(r, 400, 1); break;
          case 0x96: w(r, 380, 1); break;
          case 0x97: w(r, 1089, 1); break;
          case 0x98: w(r, 1098, 1); break;
          case 0x99: w(r, 1104, 1); break;
          case 0x9a: w(r, 1256, 2); break;
          case 0x9b: w(r, 43, 1); break;
          case 0xa0: w(r, 491, 1); break;
          case 0xa1: w(r, 40, 1); break;
          case 0xa2: w(r, 491, 1); break;
          case 0xa3: w(r, 40, 1); break;
          case 0xa4: w(r, 491, 1); break;
          case 0xa5: w(r, 40, 1); break;
          case 0xa6: w(r, 491, 1); break;
          case 0xa7: w(r, 40, 1); break;
          case 0xa8: w(r, 491, 1); break;
          case 0xa9: w(r, 40, 1); break;
          case 0xaa: w(r, 491, 1); break;
          case 0xab: w(r, 40, 1); break;
          case 0xac: w(r, 491, 1); break;
          case 0xad: w(r, 40, 1); break;
          case 0xae: w(r, 491, 1); break;
          case 0xaf: w(r, 40, 1); break;
          case 0xb0: w(r, 491, 1); break;
          case 0xb1: w(r, 40, 1); break;
          case 0xb2: w(r, 491, 1); break;
          case 0xb3: w(r, 40, 1); break;
          case 0xb4: w(r, 491, 1); break;
          case 0xb5: w(r, 40, 1); break;
          case 0xb6: w(r, 491, 1); break;
          case 0xb7: w(r, 40, 1); break;
          case 0xb8: w(r, 921, 1); break;
          case 0xb9: w(r, 518, 1); break;
          case 0xba: w(r, 921, 1); break;
          case 0xbb: w(r, 518, 1); break;
          case 0xbc: w(r, 921, 1); break;
          case 0xbd: w(r, 518, 1); break;
          case 0xbe: w(r, 921, 1); break;
          case 0xbf: w(r, 518, 1); break;
          case 0xc0: w(r, 921, 1); break;
          case 0xc1: w(r, 518, 1); break;
          case 0xc2: w(r, 921, 1); break;
          case 0xc3: w(r, 518, 1); break;
          case 0xc4: w(r, 921, 1); break;
          case 0xc5: w(r, 518, 1); break;
          case 0xc6: w(r, 921, 1); break;
          case 0xc7: w(r, 518, 1); break;
          case 0xc8: w(r, 163, 1); break;
          case 0xc9: w(r, 167, 1); break;
          case 0xca: w(r, 163, 1); break;
          case 0xcb: w(r, 167, 1); break;
          case 0xcc: w(r, 1125, 1); break;
          case 0xcd: w(r, 480, 1); break;
          case 0xce: w(r, 1125, 1); break;
          case 0xcf: w(r, 480, 1); break;
          case 0xd0: w(r, 1125, 1); break;
          case 0xd1: w(r, 480, 1); break;
          case 0xd2: w(r, 1125, 1); break;
          case 0xd3: w(r, 480, 1); break;
          case 0xd4: w(r, 1125, 1); break;
          case 0xd5: w(r, 480, 1); break;
          case 0xd6: w(r, 1125, 1); break;
          case 0xd7: w(r, 480, 1); break;
          case 0xd8: w(r, 1125, 1); break;
          case 0xd9: w(r, 480, 1); break;
          case 0xda: w(r, 1125, 1); break;
          case 0xdb: w(r, 480, 1); break;
          case 0xdc: w(r, 1125, 1); break;
          case 0xdd: w(r, 480, 1); break;
          case 0xde: w(r, 1125, 1); break;
          case 0xdf: w(r, 480, 1); break;
          case 0xe0: w(r, 1125, 1); break;
          case 0xe1: w(r, 480, 1); break;
          case 0xe2: w(r, 1125, 1); break;
          case 0xe3: w(r, 480, 1); break;
          case 0xe4: w(r, 1143, 1); break;
          case 0xe5: w(r, 967, 1); break;
          case 0xe6: w(r, 1143, 1); break;
          case 0xe7: w(r, 967, 1); break;
          case 0xe8: w(r, 1143, 1); break;
          case 0xe9: w(r, 967, 1); break;
          case 0xea: w(r, 1143, 1); break;
          case 0xeb: w(r, 967, 1); break;
          case 0xec: w(r, 1143, 1); break;
          case 0xed: w(r, 967, 1); break;
          case 0xee: w(r, 1143, 1); break;
          case 0xef: w(r, 967, 1); break;
          case 0xf0: w(r, 1143, 1); break;
          case 0xf1: w(r, 967, 1); break;
          case 0xf2: w(r, 1155, 1); break;
          case 0xf3: w(r, 1104, 1); break;
          case 0xf4: w(r, 1155, 1); break;
          case 0xf5: w(r, 1104, 1); break;
          case 0xf6: w(r, 1155, 1); break;
          case 0xf7: w(r, 1104, 1); break;
          case 0xf8: w(r, 1155, 1); break;
          case 0xf9: w(r, 1104, 1); break;
          default: r.push_back(c);
          }
        }
        break;
        case 0x1f00:
        {
          switch (static_cast<uint8_t>(c & 0xff))
          {
          case 0x0: w(r, 1832, 1); break;
          case 0x1: w(r, 1832, 1); break;
          case 0x2: w(r, 1832, 1); break;
          case 0x3: w(r, 1832, 1); break;
          case 0x4: w(r, 1832, 1); break;
          case 0x5: w(r, 1832, 1); break;
          case 0x6: w(r, 1832, 1); break;
          case 0x7: w(r, 1832, 1); break;
          case 0x8: w(r, 1820, 1); break;
          case 0x9: w(r, 1820, 1); break;
          case 0xa: w(r, 1820, 1); break;
          case 0xb: w(r, 1820, 1); break;
          case 0xc: w(r, 1820, 1); break;
          case 0xd: w(r, 1820, 1); break;
          case 0xe: w(r, 1820, 1); break;
          case 0xf: w(r, 1820, 1); break;
          case 0x10: w(r, 1828, 1); break;
          case 0x11: w(r, 1828, 1); break;
          case 0x12: w(r, 1828, 1); break;
          case 0x13: w(r, 1828, 1); break;
          case 0x14: w(r, 1828, 1); break;
          case 0x15: w(r, 1828, 1); break;
          case 0x18: w(r, 1816, 1); break;
          case 0x19: w(r, 1816, 1); break;
          case 0x1a: w(r, 1816, 1); break;
          case 0x1b: w(r, 1816, 1); break;
          case 0x1c: w(r, 1816, 1); break;
          case 0x1d: w(r, 1816, 1); break;
          case 0x20: w(r, 1857, 1); break;
          case 0x21: w(r, 1857, 1); break;
          case 0x22: w(r, 1857, 1); break;
          case 0x23: w(r, 1857, 1); break;
          case 0x24: w(r, 1857, 1); break;
          case 0x25: w(r, 1857, 1); break;
          case 0x26: w(r, 1857, 1); break;
          case 0x27: w(r, 1857, 1); break;
          case 0x28: w(r, 1814, 1); break;
          case 0x29: w(r, 1814, 1); break;
          case 0x2a: w(r, 1814, 1); break;
          case 0x2b: w(r, 1814, 1); break;
          case 0x2c: w(r, 1814, 1); break;
          case 0x2d: w(r, 1814, 1); break;
          case 0x2e: w(r, 1814, 1); break;
          case 0x2f: w(r, 1814, 1); break;
          case 0x30: w(r, 1856, 1); break;
          case 0x31: w(r, 1856, 1); break;
          case 0x32: w(r, 1856, 1); break;
          case 0x33: w(r, 1856, 1); break;
          case 0x34: w(r, 1856, 1); break;
          case 0x35: w(r, 1856, 1); break;
          case 0x36: w(r, 1856, 1); break;
          case 0x37: w(r, 1856, 1); break;
          case 0x38: w(r, 1812, 1); break;
          case 0x39: w(r, 1812, 1); break;
          case 0x3a: w(r, 1812, 1); break;
          case 0x3b: w(r, 1812, 1); break;
          case 0x3c: w(r, 1812, 1); break;
          case 0x3d: w(r, 1812, 1); break;
          case 0x3e: w(r, 1812, 1); break;
          case 0x3f: w(r, 1812, 1); break;
          case 0x40: w(r, 1852, 1); break;
          case 0x41: w(r, 1852, 1); break;
          case 0x42: w(r, 1852, 1); break;
          case 0x43: w(r, 1852, 1); break;
          case 0x44: w(r, 1852, 1); break;
          case 0x45: w(r, 1852, 1); break;
          case 0x48: w(r, 1842, 1); break;
          case 0x49: w(r, 1842, 1); break;
          case 0x4a: w(r, 1842, 1); break;
          case 0x4b: w(r, 1842, 1); break;
          case 0x4c: w(r, 1842, 1); break;
          case 0x4d: w(r, 1842, 1); break;
          case 0x50: w(r, 1848, 1); break;
          case 0x51: w(r, 1848, 1); break;
          case 0x52: w(r, 1848, 1); break;
          case 0x53: w(r, 1848, 1); break;
          case 0x54: w(r, 1848, 1); break;
          case 0x55: w(r, 1848, 1); break;
          case 0x56: w(r, 1848, 1); break;
          case 0x57: w(r, 1848, 1); break;
          case 0x59: w(r, 1837, 1); break;
          case 0x5b: w(r, 1837, 1); break;
          case 0x5d: w(r, 1837, 1); break;
          case 0x5f: w(r, 1837, 1); break;
          case 0x60: w(r, 1830, 1); break;
          case 0x61: w(r, 1830, 1); break;
          case 0x62: w(r, 1830, 1); break;
          case 0x63: w(r, 1830, 1); break;
          case 0x64: w(r, 1830, 1); break;
          case 0x65: w(r, 1830, 1); break;
          case 0x66: w(r, 1830, 1); break;
          case 0x67: w(r, 1830, 1); break;
          case 0x68: w(r, 1333, 1); break;
          case 0x69: w(r, 1333, 1); break;
          case 0x6a: w(r, 1333, 1); break;
          case 0x6b: w(r, 1333, 1); break;
          case 0x6c: w(r, 1333, 1); break;
          case 0x6d: w(r, 1333, 1); break;
          case 0x6e: w(r, 1333, 1); break;
          case 0x6f: w(r, 1333, 1); break;
          case 0x70: w(r, 1832, 1); break;
          case 0x71: w(r, 1832, 1); break;
          case 0x72: w(r, 1828, 1); break;
          case 0x73: w(r, 1828, 1); break;
          case 0x74: w(r, 1857, 1); break;
          case 0x75: w(r, 1857, 1); break;
          case 0x76: w(r, 1856, 1); break;
          case 0x77: w(r, 1856, 1); break;
          case 0x78: w(r, 1852, 1); break;
          case 0x79: w(r, 1852, 1); break;
          case 0x7a: w(r, 1848, 1); break;
          case 0x7b: w(r, 1848, 1); break;
          case 0x7c: w(r, 1830, 1); break;
          case 0x7d: w(r, 1830, 1); break;
          case 0x80: w(r, 1832, 1); break;
          case 0x81: w(r, 1832, 1); break;
          case 0x82: w(r, 1832, 1); break;
          case 0x83: w(r, 1832, 1); break;
          case 0x84: w(r, 1832, 1); break;
          case 0x85: w(r, 1832, 1); break;
          case 0x86: w(r, 1832, 1); break;
          case 0x87: w(r, 1832, 1); break;
          case 0x88: w(r, 1820, 1); break;
          case 0x89: w(r, 1820, 1); break;
          case 0x8a: w(r, 1820, 1); break;
          case 0x8b: w(r, 1820, 1); break;
          case 0x8c: w(r, 1820, 1); break;
          case 0x8d: w(r, 1820, 1); break;
          case 0x8e: w(r, 1820, 1); break;
          case 0x8f: w(r, 1820, 1); break;
          case 0x90: w(r, 1857, 1); break;
          case 0x91: w(r, 1857, 1); break;
          case 0x92: w(r, 1857, 1); break;
          case 0x93: w(r, 1857, 1); break;
          case 0x94: w(r, 1857, 1); break;
          case 0x95: w(r, 1857, 1); break;
          case 0x96: w(r, 1857, 1); break;
          case 0x97: w(r, 1857, 1); break;
          case 0x98: w(r, 1814, 1); break;
          case 0x99: w(r, 1814, 1); break;
          case 0x9a: w(r, 1814, 1); break;
          case 0x9b: w(r, 1814, 1); break;
          case 0x9c: w(r, 1814, 1); break;
          case 0x9d: w(r, 1814, 1); break;
          case 0x9e: w(r, 1814, 1); break;
          case 0x9f: w(r, 1814, 1); break;
          case 0xa0: w(r, 1830, 1); break;
          case 0xa1: w(r, 1830, 1); break;
          case 0xa2: w(r, 1830, 1); break;
          case 0xa3: w(r, 1830, 1); break;
          case 0xa4: w(r, 1830, 1); break;
          case 0xa5: w(r, 1830, 1); break;
          case 0xa6: w(r, 1830, 1); break;
          case 0xa7: w(r, 1830, 1); break;
          case 0xa8: w(r, 1333, 1); break;
          case 0xa9: w(r, 1333, 1); break;
          case 0xaa: w(r, 1333, 1); break;
          case 0xab: w(r, 1333, 1); break;
          case 0xac: w(r, 1333, 1); break;
          case 0xad: w(r, 1333, 1); break;
          case 0xae: w(r, 1333, 1); break;
          case 0xaf: w(r, 1333, 1); break;
          case 0xb0: w(r, 1832, 1); break;
          case 0xb1: w(r, 1832, 1); break;
          case 0xb2: w(r, 1832, 1); break;
          case 0xb3: w(r, 1832, 1); break;
          case 0xb4: w(r, 1832, 1); break;
          case 0xb6: w(r, 1832, 1); break;
          case 0xb7: w(r, 1832, 1); break;
          case 0xb8: w(r, 1820, 1); break;
          case 0xb9: w(r, 1820, 1); break;
          case 0xba: w(r, 1820, 1); break;
          case 0xbb: w(r, 1820, 1); break;
          case 0xbc: w(r, 1820, 1); break;
          case 0xbd: w(r, 3, 1); break;
          case 0xbe: w(r, 1856, 1); break;
          case 0xbf: w(r, 3, 1); break;
          case 0xc0: w(r, 3, 1); break;
          case 0xc1: w(r, 3, 1); break;
          case 0xc2: w(r, 1857, 1); break;
          case 0xc3: w(r, 1857, 1); break;
          case 0xc4: w(r, 1857, 1); break;
          case 0xc6: w(r, 1857, 1); break;
          case 0xc7: w(r, 1857, 1); break;
          case 0xc8: w(r, 1816, 1); break;
          case 0xc9: w(r, 1816, 1); break;
          case 0xca: w(r, 1814, 1); break;
          case 0xcb: w(r, 1814, 1); break;
          case 0xcc: w(r, 1814, 1); break;
          case 0xcd: w(r, 3, 1); break;
          case 0xce: w(r, 3, 1); break;
          case 0xcf: w(r, 3, 1); break;
          case 0xd0: w(r, 1856, 1); break;
          case 0xd1: w(r, 1856, 1); break;
          case 0xd2: w(r, 1856, 1); break;
          case 0xd3: w(r, 1856, 1); break;
          case 0xd6: w(r, 1856, 1); break;
          case 0xd7: w(r, 1856, 1); break;
          case 0xd8: w(r, 1812, 1); break;
          case 0xd9: w(r, 1812, 1); break;
          case 0xda: w(r, 1812, 1); break;
          case 0xdb: w(r, 1812, 1); break;
          case 0xdd: w(r, 3, 1); break;
          case 0xde: w(r, 3, 1); break;
          case 0xdf: w(r, 3, 1); break;
          case 0xe0: w(r, 1848, 1); break;
          case 0xe1: w(r, 1848, 1); break;
          case 0xe2: w(r, 1848, 1); break;
          case 0xe3: w(r, 1848, 1); break;
          case 0xe4: w(r, 1824, 1); break;
          case 0xe5: w(r, 1824, 1); break;
          case 0xe6: w(r, 1848, 1); break;
          case 0xe7: w(r, 1848, 1); break;
          case 0xe8: w(r, 1837, 1); break;
          case 0xe9: w(r, 1837, 1); break;
          case 0xea: w(r, 1837, 1); break;
          case 0xeb: w(r, 1837, 1); break;
          case 0xec: w(r, 1840, 1); break;
          case 0xed: w(r, 3, 1); break;
          case 0xee: w(r, 3, 1); break;
          case 0xef: w(r, 1761, 1); break;
          case 0xf2: w(r, 1830, 1); break;
          case 0xf3: w(r, 1830, 1); break;
          case 0xf4: w(r, 1830, 1); break;
          case 0xf6: w(r, 1830, 1); break;
          case 0xf7: w(r, 1830, 1); break;
          case 0xf8: w(r, 1842, 1); break;
          case 0xf9: w(r, 1842, 1); break;
          case 0xfa: w(r, 1333, 1); break;
          case 0xfb: w(r, 1333, 1); break;
          case 0xfc: w(r, 1333, 1); break;
          case 0xfd: w(r, 3, 1); break;
          case 0xfe: w(r, 3, 1); break;
          default: r.push_back(c);
          }
        }
        break;
        case 0x2000:
        {
          switch (static_cast<uint8_t>(c & 0xff))
          {
          case 0x0: w(r, 3, 1); break;
          case 0x1: w(r, 3, 1); break;
          case 0x2: w(r, 3, 1); break;
          case 0x3: w(r, 3, 1); break;
          case 0x4: w(r, 3, 1); break;
          case 0x5: w(r, 3, 1); break;
          case 0x6: w(r, 3, 1); break;
          case 0x7: w(r, 3, 1); break;
          case 0x8: w(r, 3, 1); break;
          case 0x9: w(r, 3, 1); break;
          case 0xa: w(r, 3, 1); break;
          case 0x11: w(r, 2192, 1); break;
          case 0x17: w(r, 3, 1); break;
          case 0x24: w(r, 347, 1); break;
          case 0x25: w(r, 389, 2); break;
          case 0x26: w(r, 389, 3); break;
          case 0x2f: w(r, 3, 1); break;
          case 0x33: w(r, 130, 2); break;
          case 0x34: w(r, 130, 3); break;
          case 0x36: w(r, 1232, 2); break;
          case 0x37: w(r, 1232, 3); break;
          case 0x3c: w(r, 1427, 2); break;
          case 0x3e: w(r, 3, 1); break;
          case 0x47: w(r, 1425, 2); break;
          case 0x48: w(r, 1426, 2); break;
          case 0x49: w(r, 1424, 2); break;
          case 0x57: w(r, 130, 4); break;
          case 0x5f: w(r, 3, 1); break;
          case 0x70: w(r, 161, 1); break;
          case 0x71: w(r, 167, 1); break;
          case 0x74: w(r, 188, 1); break;
          case 0x75: w(r, 192, 1); break;
          case 0x76: w(r, 196, 1); break;
          case 0x77: w(r, 200, 1); break;
          case 0x78: w(r, 204, 1); break;
          case 0x79: w(r, 208, 1); break;
          case 0x7a: w(r, 1773, 1); break;
          case 0x7b: w(r, 2191, 1); break;
          case 0x7c: w(r, 1109, 1); break;
          case 0x7d: w(r, 26, 1); break;
          case 0x7e: w(r, 32, 1); break;
          case 0x7f: w(r, 1059, 1); break;
          case 0x80: w(r, 161, 1); break;
          case 0x81: w(r, 158, 1); break;
          case 0x82: w(r, 44, 1); break;
          case 0x83: w(r, 184, 1); break;
          case 0x84: w(r, 188, 1); break;
          case 0x85: w(r, 192, 1); break;
          case 0x86: w(r, 196, 1); break;
          case 0x87: w(r, 200, 1); break;
          case 0x88: w(r, 204, 1); break;
          case 0x89: w(r, 208, 1); break;
          case 0x8a: w(r, 1773, 1); break;
          case 0x8b: w(r, 2191, 1); break;
          case 0x8c: w(r, 1109, 1); break;
          case 0x8d: w(r, 26, 1); break;
          case 0x8e: w(r, 32, 1); break;
          case 0x90: w(r, 40, 1); break;
          case 0x91: w(r, 518, 1); break;
          case 0x92: w(r, 480, 1); break;
          case 0x93: w(r, 872, 1); break;
          case 0x94: w(r, 1922, 1); break;
          case 0x95: w(r, 380, 1); break;
          case 0x96: w(r, 330, 1); break;
          case 0x97: w(r, 333, 1); break;
          case 0x98: w(r, 334, 1); break;
          case 0x99: w(r, 1059, 1); break;
          case 0x9a: w(r, 366, 1); break;
          case 0x9b: w(r, 43, 1); break;
          case 0x9c: w(r, 1089, 1); break;
          case 0xa8: w(r, 1430, 2); break;
          default: r.push_back(c);
          }
        }
        break;
        case 0x2100:
        {
          switch (static_cast<uint8_t>(c & 0xff))
          {
          case 0x0: w(r, 956, 3); break;
          case 0x1: w(r, 959, 3); break;
          case 0x2: w(r, 358, 1); break;
          case 0x3: w(r, 1432, 2); break;
          case 0x5: w(r, 962, 3); break;
          case 0x6: w(r, 965, 3); break;
          case 0x7: w(r, 2229, 1); break;
          case 0x9: w(r, 1434, 2); break;
          case 0xa: w(r, 361, 1); break;
          case 0xb: w(r, 399, 1); break;
          case 0xc: w(r, 399, 1); break;
          case 0xd: w(r, 399, 1); break;
          case 0xe: w(r, 380, 1); break;
          case 0xf: w(r, 2228, 1); break;
          case 0x10: w(r, 163, 1); break;
          case 0x11: w(r, 163, 1); break;
          case 0x12: w(r, 515, 1); break;
          case 0x13: w(r, 333, 1); break;
          case 0x15: w(r, 1122, 1); break;
          case 0x16: w(r, 1438, 2); break;
          case 0x19: w(r, 381, 1); break;
          case 0x1a: w(r, 1131, 1); break;
          case 0x1b: w(r, 1134, 1); break;
          case 0x1c: w(r, 1134, 1); break;
          case 0x1d: w(r, 1134, 1); break;
          case 0x20: w(r, 1442, 2); break;
          case 0x21: w(r, 968, 3); break;
          case 0x22: w(r, 1444, 2); break;
          case 0x24: w(r, 1158, 1); break;
          case 0x26: w(r, 1333, 1); break;
          case 0x28: w(r, 1158, 1); break;
          case 0x2a: w(r, 939, 1); break;
          case 0x2b: w(r, 491, 1); break;
          case 0x2c: w(r, 912, 1); break;
          case 0x2d: w(r, 358, 1); break;
          case 0x2f: w(r, 518, 1); break;
          case 0x30: w(r, 921, 1); break;
          case 0x31: w(r, 924, 1); break;
          case 0x33: w(r, 401, 1); break;
          case 0x34: w(r, 480, 1); break;
          case 0x35: w(r, 1722, 1); break;
          case 0x36: w(r, 2159, 1); break;
          case 0x37: w(r, 2160, 1); break;
          case 0x38: w(r, 2151, 1); break;
          case 0x39: w(r, 167, 1); break;
          case 0x3b: w(r, 974, 3); break;
          case 0x3c: w(r, 1823, 1); break;
          case 0x3d: w(r, 1845, 1); break;
          case 0x3e: w(r, 1818, 1); break;
          case 0x3f: w(r, 1841, 1); break;
          case 0x40: w(r, 2250, 1); break;
          case 0x45: w(r, 517, 1); break;
          case 0x46: w(r, 41, 1); break;
          case 0x47: w(r, 518, 1); break;
          case 0x48: w(r, 167, 1); break;
          case 0x49: w(r, 1047, 1); break;
          case 0x50: w(r, 977, 3); break;
          case 0x51: w(r, 980, 3); break;
          case 0x52: w(r, 158, 4); break;
          case 0x53: w(r, 983, 3); break;
          case 0x54: w(r, 986, 3); break;
          case 0x55: w(r, 989, 3); break;
          case 0x56: w(r, 992, 3); break;
          case 0x57: w(r, 995, 3); break;
          case 0x58: w(r, 998, 3); break;
          case 0x59: w(r, 1001, 3); break;
          case 0x5a: w(r, 1004, 3); break;
          case 0x5b: w(r, 1007, 3); break;
          case 0x5c: w(r, 1010, 3); break;
          case 0x5d: w(r, 1013, 3); break;
          case 0x5e: w(r, 1016, 3); break;
          case 0x5f: w(r, 158, 2); break;
          case 0x60: w(r, 163, 1); break;
          case 0x61: w(r, 163, 2); break;
          case 0x62: w(r, 163, 3); break;
          case 0x63: w(r, 1416, 2); break;
          case 0x64: w(r, 162, 1); break;
          case 0x65: w(r, 162, 2); break;
          case 0x66: w(r, 162, 3); break;
          case 0x67: w(r, 162, 4); break;
          case 0x68: w(r, 1418, 2); break;
          case 0x69: w(r, 869, 1); break;
          case 0x6a: w(r, 869, 2); break;
          case 0x6b: w(r, 869, 3); break;
          case 0x6c: w(r, 515, 1); break;
          case 0x6d: w(r, 358, 1); break;
          case 0x6e: w(r, 517, 1); break;
          case 0x6f: w(r, 401, 1); break;
          case 0x70: w(r, 167, 1); break;
          case 0x71: w(r, 167, 2); break;
          case 0x72: w(r, 167, 3); break;
          case 0x73: w(r, 1422, 2); break;
          case 0x74: w(r, 166, 1); break;
          case 0x75: w(r, 166, 2); break;
          case 0x76: w(r, 166, 3); break;
          case 0x77: w(r, 166, 4); break;
          case 0x78: w(r, 1454, 2); break;
          case 0x79: w(r, 872, 1); break;
          case 0x7a: w(r, 872, 2); break;
          case 0x7b: w(r, 872, 3); break;
          case 0x7c: w(r, 333, 1); break;
          case 0x7d: w(r, 331, 1); break;
          case 0x7e: w(r, 41, 1); break;
          case 0x7f: w(r, 334, 1); break;
          case 0x89: w(r, 875, 3); break;
          case 0x9a: w(r, 1909, 1); break;
          case 0x9b: w(r, 1907, 1); break;
          case 0xae: w(r, 2230, 1); break;
          case 0xcd: w(r, 2231, 1); break;
          case 0xce: w(r, 2232, 1); break;
          case 0xcf: w(r, 2233, 1); break;
          default: r.push_back(c);
          }
        }
        break;
        case 0x2200:
        {
          switch (static_cast<uint8_t>(c & 0xff))
          {
          case 0x4: w(r, 2234, 1); break;
          case 0x9: w(r, 2235, 1); break;
          case 0xc: w(r, 2236, 1); break;
          case 0x24: w(r, 2237, 1); break;
          case 0x26: w(r, 2238, 1); break;
          case 0x2c: w(r, 370, 2); break;
          case 0x2d: w(r, 370, 3); break;
          case 0x2f: w(r, 878, 2); break;
          case 0x30: w(r, 878, 3); break;
          case 0x41: w(r, 2239, 1); break;
          case 0x44: w(r, 2240, 1); break;
          case 0x47: w(r, 2241, 1); break;
          case 0x49: w(r, 2242, 1); break;
          case 0x60: w(r, 1109, 1); break;
          case 0x62: w(r, 2243, 1); break;
          case 0x6d: w(r, 2244, 1); break;
          case 0x6e: w(r, 1775, 1); break;
          case 0x6f: w(r, 1776, 1); break;
          case 0x70: w(r, 2245, 1); break;
          case 0x71: w(r, 2246, 1); break;
          case 0x74: w(r, 2247, 1); break;
          case 0x75: w(r, 2248, 1); break;
          case 0x78: w(r, 2249, 1); break;
          case 0x79: w(r, 2193, 1); break;
          case 0x80: w(r, 2194, 1); break;
          case 0x81: w(r, 2195, 1); break;
          case 0x84: w(r, 2196, 1); break;
          case 0x85: w(r, 2197, 1); break;
          case 0x88: w(r, 2198, 1); break;
          case 0x89: w(r, 2199, 1); break;
          case 0xac: w(r, 2200, 1); break;
          case 0xad: w(r, 2201, 1); break;
          case 0xae: w(r, 2202, 1); break;
          case 0xaf: w(r, 2203, 1); break;
          case 0xe0: w(r, 2204, 1); break;
          case 0xe1: w(r, 2205, 1); break;
          case 0xe2: w(r, 2206, 1); break;
          case 0xe3: w(r, 2207, 1); break;
          case 0xea: w(r, 2208, 1); break;
          case 0xeb: w(r, 2209, 1); break;
          case 0xec: w(r, 2210, 1); break;
          case 0xed: w(r, 2211, 1); break;
          default: r.push_back(c);
          }
        }
        break;
        case 0x2300:
        {
          switch (static_cast<uint8_t>(c & 0xff))
          {
          case 0x29: w(r, 1784, 1); break;
          case 0x2a: w(r, 1783, 1); break;
          default: r.push_back(c);
          }
        }
        break;
        case 0x2400:
        {
          switch (static_cast<uint8_t>(c & 0xff))
          {
          case 0x60: w(r, 158, 1); break;
          case 0x61: w(r, 44, 1); break;
          case 0x62: w(r, 184, 1); break;
          case 0x63: w(r, 188, 1); break;
          case 0x64: w(r, 192, 1); break;
          case 0x65: w(r, 196, 1); break;
          case 0x66: w(r, 200, 1); break;
          case 0x67: w(r, 204, 1); break;
          case 0x68: w(r, 208, 1); break;
          case 0x69: w(r, 160, 2); break;
          case 0x6a: w(r, 175, 2); break;
          case 0x6b: w(r, 179, 2); break;
          case 0x6c: w(r, 183, 2); break;
          case 0x6d: w(r, 187, 2); break;
          case 0x6e: w(r, 191, 2); break;
          case 0x6f: w(r, 195, 2); break;
          case 0x70: w(r, 199, 2); break;
          case 0x71: w(r, 203, 2); break;
          case 0x72: w(r, 207, 2); break;
          case 0x73: w(r, 211, 2); break;
          case 0x74: w(r, 881, 3); break;
          case 0x75: w(r, 884, 3); break;
          case 0x76: w(r, 887, 3); break;
          case 0x77: w(r, 890, 3); break;
          case 0x78: w(r, 893, 3); break;
          case 0x79: w(r, 896, 3); break;
          case 0x7a: w(r, 899, 3); break;
          case 0x7b: w(r, 902, 3); break;
          case 0x7c: w(r, 905, 3); break;
          case 0x7d: w(r, 170, 4); break;
          case 0x7e: w(r, 174, 4); break;
          case 0x7f: w(r, 178, 4); break;
          case 0x80: w(r, 182, 4); break;
          case 0x81: w(r, 186, 4); break;
          case 0x82: w(r, 190, 4); break;
          case 0x83: w(r, 194, 4); break;
          case 0x84: w(r, 198, 4); break;
          case 0x85: w(r, 202, 4); break;
          case 0x86: w(r, 206, 4); break;
          case 0x87: w(r, 210, 4); break;
          case 0x88: w(r, 1167, 2); break;
          case 0x89: w(r, 388, 2); break;
          case 0x8a: w(r, 1173, 2); break;
          case 0x8b: w(r, 1176, 2); break;
          case 0x8c: w(r, 1179, 2); break;
          case 0x8d: w(r, 1182, 2); break;
          case 0x8e: w(r, 1185, 2); break;
          case 0x8f: w(r, 1188, 2); break;
          case 0x90: w(r, 1191, 2); break;
          case 0x91: w(r, 1163, 3); break;
          case 0x92: w(r, 1166, 3); break;
          case 0x93: w(r, 1169, 3); break;
          case 0x94: w(r, 1172, 3); break;
          case 0x95: w(r, 1175, 3); break;
          case 0x96: w(r, 1178, 3); break;
          case 0x97: w(r, 1181, 3); break;
          case 0x98: w(r, 1184, 3); break;
          case 0x99: w(r, 1187, 3); break;
          case 0x9a: w(r, 1190, 3); break;
          case 0x9b: w(r, 1193, 3); break;
          case 0x9c: w(r, 1196, 3); break;
          case 0x9d: w(r, 1199, 3); break;
          case 0x9e: w(r, 1202, 3); break;
          case 0x9f: w(r, 1028, 3); break;
          case 0xa0: w(r, 1031, 3); break;
          case 0xa1: w(r, 1034, 3); break;
          case 0xa2: w(r, 1037, 3); break;
          case 0xa3: w(r, 1040, 3); break;
          case 0xa4: w(r, 1043, 3); break;
          case 0xa5: w(r, 1046, 3); break;
          case 0xa6: w(r, 1049, 3); break;
          case 0xa7: w(r, 1052, 3); break;
          case 0xa8: w(r, 1055, 3); break;
          case 0xa9: w(r, 1058, 3); break;
          case 0xaa: w(r, 1064, 3); break;
          case 0xab: w(r, 1067, 3); break;
          case 0xac: w(r, 1070, 3); break;
          case 0xad: w(r, 1073, 3); break;
          case 0xae: w(r, 1076, 3); break;
          case 0xaf: w(r, 1088, 3); break;
          case 0xb0: w(r, 1091, 3); break;
          case 0xb1: w(r, 1094, 3); break;
          case 0xb2: w(r, 1097, 3); break;
          case 0xb3: w(r, 1100, 3); break;
          case 0xb4: w(r, 1103, 3); break;
          case 0xb5: w(r, 1106, 3); break;
          case 0xb6: w(r, 491, 1); break;
          case 0xb7: w(r, 912, 1); break;
          case 0xb8: w(r, 358, 1); break;
          case 0xb9: w(r, 517, 1); break;
          case 0xba: w(r, 921, 1); break;
          case 0xbb: w(r, 924, 1); break;
          case 0xbc: w(r, 404, 1); break;
          case 0xbd: w(r, 399, 1); break;
          case 0xbe: w(r, 163, 1); break;
          case 0xbf: w(r, 936, 1); break;
          case 0xc0: w(r, 939, 1); break;
          case 0xc1: w(r, 515, 1); break;
          case 0xc2: w(r, 401, 1); break;
          case 0xc3: w(r, 1122, 1); break;
          case 0xc4: w(r, 1125, 1); break;
          case 0xc5: w(r, 381, 1); break;
          case 0xc6: w(r, 1131, 1); break;
          case 0xc7: w(r, 1134, 1); break;
          case 0xc8: w(r, 1137, 1); break;
          case 0xc9: w(r, 407, 1); break;
          case 0xca: w(r, 1143, 1); break;
          case 0xcb: w(r, 162, 1); break;
          case 0xcc: w(r, 1149, 1); break;
          case 0xcd: w(r, 869, 1); break;
          case 0xce: w(r, 1155, 1); break;
          case 0xcf: w(r, 1158, 1); break;
          case 0xd0: w(r, 40, 1); break;
          case 0xd1: w(r, 383, 1); break;
          case 0xd2: w(r, 331, 1); break;
          case 0xd3: w(r, 41, 1); break;
          case 0xd4: w(r, 518, 1); break;
          case 0xd5: w(r, 593, 1); break;
          case 0xd6: w(r, 361, 1); break;
          case 0xd7: w(r, 380, 1); break;
          case 0xd8: w(r, 167, 1); break;
          case 0xd9: w(r, 1047, 1); break;
          case 0xda: w(r, 330, 1); break;
          case 0xdb: w(r, 333, 1); break;
          case 0xdc: w(r, 334, 1); break;
          case 0xdd: w(r, 1059, 1); break;
          case 0xde: w(r, 480, 1); break;
          case 0xdf: w(r, 366, 1); break;
          case 0xe0: w(r, 1071, 1); break;
          case 0xe1: w(r, 39, 1); break;
          case 0xe2: w(r, 43, 1); break;
          case 0xe3: w(r, 1089, 1); break;
          case 0xe4: w(r, 967, 1); break;
          case 0xe5: w(r, 166, 1); break;
          case 0xe6: w(r, 1098, 1); break;
          case 0xe7: w(r, 872, 1); break;
          case 0xe8: w(r, 1104, 1); break;
          case 0xe9: w(r, 400, 1); break;
          case 0xea: w(r, 161, 1); break;
          default: r.push_back(c);
          }
        }
        break;
        case 0x2a00:
        {
          switch (static_cast<uint8_t>(c & 0xff))
          {
          case 0xc: w(r, 370, 4); break;
          case 0x74: w(r, 1112, 3); break;
          case 0x75: w(r, 1109, 2); break;
          case 0x76: w(r, 1109, 3); break;
          case 0xdc: w(r, 2212, 1); break;
          default: r.push_back(c);
          }
        }
        break;
        case 0x2c00:
        {
          switch (static_cast<uint8_t>(c & 0xff))
          {
          case 0x7c: w(r, 1047, 1); break;
          case 0x7d: w(r, 162, 1); break;
          default: r.push_back(c);
          }
        }
        break;
        case 0x2d00:
        {
          switch (static_cast<uint8_t>(c & 0xff))
          {
          case 0x6f: w(r, 2213, 1); break;
          default: r.push_back(c);
          }
        }
        break;
        case 0x2f00:
        {
          switch (static_cast<uint8_t>(c & 0xff))
          {
          case 0x0: w(r, 1209, 1); break;
          default: r.push_back(c);
          }
        }
        break;
        case 0x3000:
        {
          switch (static_cast<uint8_t>(c & 0xff))
          {
          case 0x0: w(r, 3, 1); break;
          case 0x36: w(r, 2214, 1); break;
          case 0x4c: w(r, 1639, 1); break;
          case 0x4e: w(r, 2215, 1); break;
          case 0x50: w(r, 2216, 1); break;
          case 0x52: w(r, 2217, 1); break;
          case 0x54: w(r, 2218, 1); break;
          case 0x56: w(r, 2219, 1); break;
          case 0x58: w(r, 2220, 1); break;
          case 0x5a: w(r, 2221, 1); break;
          case 0x5c: w(r, 2222, 1); break;
          case 0x5e: w(r, 2223, 1); break;
          case 0x60: w(r, 2224, 1); break;
          case 0x62: w(r, 2225, 1); break;
          case 0x65: w(r, 2226, 1); break;
          case 0x67: w(r, 2227, 1); break;
          case 0x69: w(r, 2092, 1); break;
          case 0x70: w(r, 2093, 1); break;
          case 0x71: w(r, 2093, 1); break;
          case 0x73: w(r, 2095, 1); break;
          case 0x74: w(r, 2095, 1); break;
          case 0x76: w(r, 2097, 1); break;
          case 0x77: w(r, 2097, 1); break;
          case 0x79: w(r, 2099, 1); break;
          case 0x7a: w(r, 2099, 1); break;
          case 0x7c: w(r, 1638, 1); break;
          case 0x7d: w(r, 1638, 1); break;
          case 0x94: w(r, 2101, 1); break;
          case 0x9b: w(r, 3, 1); break;
          case 0x9c: w(r, 3, 1); break;
          case 0x9e: w(r, 2102, 1); break;
          case 0x9f: w(r, 1460, 2); break;
          case 0xac: w(r, 135, 1); break;
          case 0xae: w(r, 45, 1); break;
          case 0xb0: w(r, 81, 1); break;
          case 0xb2: w(r, 54, 1); break;
          case 0xb4: w(r, 575, 1); break;
          case 0xb6: w(r, 71, 1); break;
          case 0xb8: w(r, 103, 1); break;
          case 0xba: w(r, 63, 1); break;
          case 0xbc: w(r, 68, 1); break;
          case 0xbe: w(r, 1407, 1); break;
          case 0xc0: w(r, 113, 1); break;
          case 0xc2: w(r, 73, 1); break;
          case 0xc5: w(r, 454, 1); break;
          case 0xc7: w(r, 1456, 1); break;
          case 0xc9: w(r, 49, 1); break;
          case 0xd0: w(r, 66, 1); break;
          case 0xd1: w(r, 66, 1); break;
          case 0xd3: w(r, 61, 1); break;
          case 0xd4: w(r, 61, 1); break;
          case 0xd6: w(r, 56, 1); break;
          case 0xd7: w(r, 56, 1); break;
          case 0xd9: w(r, 111, 1); break;
          case 0xda: w(r, 111, 1); break;
          case 0xdc: w(r, 142, 1); break;
          case 0xdd: w(r, 142, 1); break;
          case 0xf4: w(r, 497, 1); break;
          case 0xf7: w(r, 93, 1); break;
          case 0xf8: w(r, 2089, 1); break;
          case 0xf9: w(r, 2090, 1); break;
          case 0xfa: w(r, 1758, 1); break;
          case 0xfe: w(r, 2091, 1); break;
          case 0xff: w(r, 1458, 2); break;
          default: r.push_back(c);
          }
        }
        break;
        case 0x3100:
        {
          switch (static_cast<uint8_t>(c & 0xff))
          {
          case 0x31: w(r, 124, 1); break;
          case 0x32: w(r, 1868, 1); break;
          case 0x33: w(r, 1867, 1); break;
          case 0x34: w(r, 323, 1); break;
          case 0x35: w(r, 1866, 1); break;
          case 0x36: w(r, 1865, 1); break;
          case 0x37: w(r, 319, 1); break;
          case 0x38: w(r, 1864, 1); break;
          case 0x39: w(r, 315, 1); break;
          case 0x3a: w(r, 1863, 1); break;
          case 0x3b: w(r, 1862, 1); break;
          case 0x3c: w(r, 1861, 1); break;
          case 0x3d: w(r, 1860, 1); break;
          case 0x3e: w(r, 1876, 1); break;
          case 0x3f: w(r, 1875, 1); break;
          case 0x40: w(r, 1874, 1); break;
          case 0x41: w(r, 311, 1); break;
          case 0x42: w(r, 307, 1); break;
          case 0x43: w(r, 1873, 1); break;
          case 0x44: w(r, 1872, 1); break;
          case 0x45: w(r, 303, 1); break;
          case 0x46: w(r, 1871, 1); break;
          case 0x47: w(r, 27, 1); break;
          case 0x48: w(r, 29, 1); break;
          case 0x49: w(r, 1870, 1); break;
          case 0x4a: w(r, 121, 1); break;
          case 0x4b: w(r, 287, 1); break;
          case 0x4c: w(r, 283, 1); break;
          case 0x4d: w(r, 279, 1); break;
          case 0x4e: w(r, 36, 1); break;
          case 0x4f: w(r, 122, 1); break;
          case 0x50: w(r, 1901, 1); break;
          case 0x51: w(r, 1900, 1); break;
          case 0x52: w(r, 1899, 1); break;
          case 0x53: w(r, 30, 1); break;
          case 0x54: w(r, 1898, 1); break;
          case 0x55: w(r, 1897, 1); break;
          case 0x56: w(r, 1896, 1); break;
          case 0x57: w(r, 28, 1); break;
          case 0x58: w(r, 1895, 1); break;
          case 0x59: w(r, 1894, 1); break;
          case 0x5a: w(r, 1893, 1); break;
          case 0x5b: w(r, 1892, 1); break;
          case 0x5c: w(r, 37, 1); break;
          case 0x5d: w(r, 1891, 1); break;
          case 0x5e: w(r, 1890, 1); break;
          case 0x5f: w(r, 1889, 1); break;
          case 0x60: w(r, 1888, 1); break;
          case 0x61: w(r, 1887, 1); break;
          case 0x62: w(r, 217, 1); break;
          case 0x63: w(r, 1917, 1); break;
          case 0x64: w(r, 1869, 1); break;
          case 0x65: w(r, 2103, 1); break;
          case 0x66: w(r, 2104, 1); break;
          case 0x67: w(r, 2105, 1); break;
          case 0x68: w(r, 2106, 1); break;
          case 0x69: w(r, 2107, 1); break;
          case 0x6a: w(r, 2108, 1); break;
          case 0x6b: w(r, 2063, 1); break;
          case 0x6c: w(r, 2064, 1); break;
          case 0x6d: w(r, 2065, 1); break;
          case 0x6e: w(r, 2066, 1); break;
          case 0x6f: w(r, 2067, 1); break;
          case 0x70: w(r, 2068, 1); break;
          case 0x71: w(r, 2069, 1); break;
          case 0x72: w(r, 2070, 1); break;
          case 0x73: w(r, 2071, 1); break;
          case 0x74: w(r, 2072, 1); break;
          case 0x75: w(r, 2073, 1); break;
          case 0x76: w(r, 2074, 1); break;
          case 0x77: w(r, 2075, 1); break;
          case 0x78: w(r, 2076, 1); break;
          case 0x79: w(r, 2077, 1); break;
          case 0x7a: w(r, 2078, 1); break;
          case 0x7b: w(r, 2079, 1); break;
          case 0x7c: w(r, 2080, 1); break;
          case 0x7d: w(r, 2081, 1); break;
          case 0x7e: w(r, 2082, 1); break;
          case 0x7f: w(r, 2083, 1); break;
          case 0x80: w(r, 2084, 1); break;
          case 0x81: w(r, 2085, 1); break;
          case 0x82: w(r, 2086, 1); break;
          case 0x83: w(r, 2087, 1); break;
          case 0x84: w(r, 2088, 1); break;
          case 0x85: w(r, 2053, 1); break;
          case 0x86: w(r, 2054, 1); break;
          case 0x87: w(r, 2055, 1); break;
          case 0x88: w(r, 2056, 1); break;
          case 0x89: w(r, 2057, 1); break;
          case 0x8a: w(r, 2058, 1); break;
          case 0x8b: w(r, 2059, 1); break;
          case 0x8c: w(r, 2060, 1); break;
          case 0x8d: w(r, 2061, 1); break;
          case 0x8e: w(r, 2062, 1); break;
          case 0x92: w(r, 1209, 1); break;
          default: r.push_back(c);
          }
        }
        break;
        case 0x3200:
        {
          switch (static_cast<uint8_t>(c & 0xff))
          {
          case 0x0: w(r, 953, 3); break;
          case 0x1: w(r, 950, 3); break;
          case 0x2: w(r, 947, 3); break;
          case 0x3: w(r, 944, 3); break;
          case 0x4: w(r, 941, 3); break;
          case 0x5: w(r, 1238, 3); break;
          case 0x6: w(r, 1226, 3); break;
          case 0x7: w(r, 1241, 3); break;
          case 0x8: w(r, 1235, 3); break;
          case 0x9: w(r, 1229, 3); break;
          case 0xa: w(r, 1220, 3); break;
          case 0xb: w(r, 1217, 3); break;
          case 0xc: w(r, 1214, 3); break;
          case 0xd: w(r, 1211, 3); break;
          case 0xe: w(r, 326, 4); break;
          case 0xf: w(r, 322, 4); break;
          case 0x10: w(r, 318, 4); break;
          case 0x11: w(r, 314, 4); break;
          case 0x12: w(r, 310, 4); break;
          case 0x13: w(r, 306, 4); break;
          case 0x14: w(r, 302, 4); break;
          case 0x15: w(r, 298, 4); break;
          case 0x16: w(r, 294, 4); break;
          case 0x17: w(r, 290, 4); break;
          case 0x18: w(r, 286, 4); break;
          case 0x19: w(r, 282, 4); break;
          case 0x1a: w(r, 278, 4); break;
          case 0x1b: w(r, 274, 4); break;
          case 0x1c: w(r, 270, 4); break;
          case 0x1d: w(r, 26, 7); break;
          case 0x1e: w(r, 33, 6); break;
          case 0x20: w(r, 1208, 3); break;
          case 0x21: w(r, 1412, 2); break;
          case 0x22: w(r, 1412, 2); break;
          case 0x23: w(r, 1412, 2); break;
          case 0x24: w(r, 1412, 2); break;
          case 0x25: w(r, 1412, 2); break;
          case 0x26: w(r, 1412, 2); break;
          case 0x27: w(r, 1412, 2); break;
          case 0x28: w(r, 1412, 2); break;
          case 0x29: w(r, 1412, 2); break;
          case 0x2a: w(r, 1412, 2); break;
          case 0x2b: w(r, 1412, 2); break;
          case 0x2c: w(r, 1412, 2); break;
          case 0x2d: w(r, 1412, 2); break;
          case 0x2e: w(r, 1412, 2); break;
          case 0x2f: w(r, 1412, 2); break;
          case 0x30: w(r, 1412, 2); break;
          case 0x31: w(r, 1412, 2); break;
          case 0x32: w(r, 1412, 2); break;
          case 0x33: w(r, 1412, 2); break;
          case 0x34: w(r, 1412, 2); break;
          case 0x35: w(r, 1412, 2); break;
          case 0x36: w(r, 1412, 2); break;
          case 0x37: w(r, 1412, 2); break;
          case 0x38: w(r, 1412, 2); break;
          case 0x39: w(r, 1412, 2); break;
          case 0x3a: w(r, 1412, 2); break;
          case 0x3b: w(r, 1412, 2); break;
          case 0x3c: w(r, 1412, 2); break;
          case 0x3d: w(r, 1412, 2); break;
          case 0x3e: w(r, 1412, 2); break;
          case 0x3f: w(r, 1412, 2); break;
          case 0x40: w(r, 1412, 2); break;
          case 0x41: w(r, 1412, 2); break;
          case 0x42: w(r, 1412, 2); break;
          case 0x43: w(r, 1412, 2); break;
          case 0x50: w(r, 1223, 3); break;
          case 0x51: w(r, 1084, 2); break;
          case 0x52: w(r, 1279, 2); break;
          case 0x53: w(r, 1286, 2); break;
          case 0x54: w(r, 1288, 2); break;
          case 0x55: w(r, 1448, 2); break;
          case 0x56: w(r, 1450, 2); break;
          case 0x57: w(r, 1280, 2); break;
          case 0x58: w(r, 1276, 2); break;
          case 0x59: w(r, 1274, 2); break;
          case 0x5a: w(r, 1272, 2); break;
          case 0x5b: w(r, 988, 2); break;
          case 0x5c: w(r, 985, 2); break;
          case 0x5d: w(r, 1364, 2); break;
          case 0x5e: w(r, 1366, 2); break;
          case 0x5f: w(r, 1368, 2); break;
          case 0x60: w(r, 124, 1); break;
          case 0x61: w(r, 323, 1); break;
          case 0x62: w(r, 319, 1); break;
          case 0x63: w(r, 315, 1); break;
          case 0x64: w(r, 311, 1); break;
          case 0x65: w(r, 307, 1); break;
          case 0x66: w(r, 303, 1); break;
          case 0x67: w(r, 27, 1); break;
          case 0x68: w(r, 29, 1); break;
          case 0x69: w(r, 121, 1); break;
          case 0x6a: w(r, 287, 1); break;
          case 0x6b: w(r, 283, 1); break;
          case 0x6c: w(r, 279, 1); break;
          case 0x6d: w(r, 36, 1); break;
          case 0x6e: w(r, 327, 2); break;
          case 0x6f: w(r, 323, 2); break;
          case 0x70: w(r, 319, 2); break;
          case 0x71: w(r, 315, 2); break;
          case 0x72: w(r, 311, 2); break;
          case 0x73: w(r, 307, 2); break;
          case 0x74: w(r, 303, 2); break;
          case 0x75: w(r, 299, 2); break;
          case 0x76: w(r, 295, 2); break;
          case 0x77: w(r, 121, 2); break;
          case 0x78: w(r, 287, 2); break;
          case 0x79: w(r, 283, 2); break;
          case 0x7a: w(r, 279, 2); break;
          case 0x7b: w(r, 275, 2); break;
          case 0x7c: w(r, 121, 5); break;
          case 0x7d: w(r, 214, 4); break;
          case 0x7e: w(r, 1380, 2); break;
          case 0x80: w(r, 1209, 1); break;
          case 0xb1: w(r, 1378, 2); break;
          case 0xb2: w(r, 1376, 2); break;
          case 0xb3: w(r, 1374, 2); break;
          case 0xb4: w(r, 1372, 2); break;
          case 0xb5: w(r, 1370, 2); break;
          case 0xb6: w(r, 1081, 2); break;
          case 0xb7: w(r, 1278, 2); break;
          case 0xb8: w(r, 1252, 2); break;
          case 0xb9: w(r, 1289, 2); break;
          case 0xba: w(r, 1314, 2); break;
          case 0xbb: w(r, 1316, 2); break;
          case 0xbc: w(r, 1318, 2); break;
          case 0xbd: w(r, 1324, 2); break;
          case 0xbe: w(r, 1290, 2); break;
          case 0xbf: w(r, 1284, 2); break;
          case 0xc0: w(r, 158, 1); break;
          case 0xc1: w(r, 44, 1); break;
          case 0xc2: w(r, 184, 1); break;
          case 0xc3: w(r, 188, 1); break;
          case 0xc4: w(r, 192, 1); break;
          case 0xc5: w(r, 196, 1); break;
          case 0xc6: w(r, 200, 1); break;
          case 0xc7: w(r, 204, 1); break;
          case 0xc8: w(r, 208, 1); break;
          case 0xc9: w(r, 160, 2); break;
          case 0xca: w(r, 175, 2); break;
          case 0xcb: w(r, 179, 2); break;
          case 0xcc: w(r, 1282, 2); break;
          case 0xcd: w(r, 518, 3); break;
          case 0xce: w(r, 1452, 2); break;
          case 0xcf: w(r, 515, 3); break;
          case 0xd0: w(r, 62, 1); break;
          case 0xd1: w(r, 84, 1); break;
          case 0xd2: w(r, 497, 1); break;
          case 0xd3: w(r, 106, 1); break;
          case 0xd4: w(r, 485, 1); break;
          case 0xd5: w(r, 135, 1); break;
          case 0xd6: w(r, 45, 1); break;
          case 0xd7: w(r, 81, 1); break;
          case 0xd8: w(r, 54, 1); break;
          case 0xd9: w(r, 575, 1); break;
          case 0xda: w(r, 71, 1); break;
          case 0xdb: w(r, 103, 1); break;
          case 0xdc: w(r, 63, 1); break;
          case 0xdd: w(r, 68, 1); break;
          case 0xde: w(r, 1407, 1); break;
          case 0xdf: w(r, 113, 1); break;
          case 0xe0: w(r, 73, 1); break;
          case 0xe1: w(r, 454, 1); break;
          case 0xe2: w(r, 1456, 1); break;
          case 0xe3: w(r, 49, 1); break;
          case 0xe4: w(r, 580, 1); break;
          case 0xe5: w(r, 231, 1); break;
          case 0xe6: w(r, 1877, 1); break;
          case 0xe7: w(r, 257, 1); break;
          case 0xe8: w(r, 563, 1); break;
          case 0xe9: w(r, 66, 1); break;
          case 0xea: w(r, 61, 1); break;
          case 0xeb: w(r, 56, 1); break;
          case 0xec: w(r, 111, 1); break;
          case 0xed: w(r, 142, 1); break;
          case 0xee: w(r, 101, 1); break;
          case 0xef: w(r, 76, 1); break;
          case 0xf0: w(r, 75, 1); break;
          case 0xf1: w(r, 47, 1); break;
          case 0xf2: w(r, 1879, 1); break;
          case 0xf3: w(r, 806, 1); break;
          case 0xf4: w(r, 803, 1); break;
          case 0xf5: w(r, 1878, 1); break;
          case 0xf6: w(r, 58, 1); break;
          case 0xf7: w(r, 77, 1); break;
          case 0xf8: w(r, 50, 1); break;
          case 0xf9: w(r, 51, 1); break;
          case 0xfa: w(r, 46, 1); break;
          case 0xfb: w(r, 93, 1); break;
          case 0xfc: w(r, 2089, 1); break;
          case 0xfd: w(r, 2090, 1); break;
          case 0xfe: w(r, 1758, 1); break;
          default: r.push_back(c);
          }
        }
        break;
        case 0x3300:
        {
          switch (static_cast<uint8_t>(c & 0xff))
          {
          case 0x0: w(r, 218, 4); break;
          case 0x1: w(r, 222, 4); break;
          case 0x2: w(r, 226, 4); break;
          case 0x3: w(r, 506, 3); break;
          case 0x4: w(r, 230, 4); break;
          case 0x5: w(r, 500, 3); break;
          case 0x6: w(r, 497, 3); break;
          case 0x7: w(r, 106, 5); break;
          case 0x8: w(r, 234, 4); break;
          case 0x9: w(r, 488, 3); break;
          case 0xa: w(r, 485, 3); break;
          case 0xb: w(r, 482, 3); break;
          case 0xc: w(r, 238, 4); break;
          case 0xd: w(r, 242, 4); break;
          case 0xe: w(r, 608, 3); break;
          case 0xf: w(r, 605, 3); break;
          case 0x10: w(r, 1446, 2); break;
          case 0x11: w(r, 602, 3); break;
          case 0x12: w(r, 246, 4); break;
          case 0x13: w(r, 250, 4); break;
          case 0x14: w(r, 45, 2); break;
          case 0x15: w(r, 96, 5); break;
          case 0x16: w(r, 45, 6); break;
          case 0x17: w(r, 91, 5); break;
          case 0x18: w(r, 86, 3); break;
          case 0x19: w(r, 86, 5); break;
          case 0x1a: w(r, 81, 5); break;
          case 0x1b: w(r, 254, 4); break;
          case 0x1c: w(r, 581, 3); break;
          case 0x1d: w(r, 578, 3); break;
          case 0x1e: w(r, 575, 3); break;
          case 0x1f: w(r, 258, 4); break;
          case 0x20: w(r, 71, 5); break;
          case 0x21: w(r, 262, 4); break;
          case 0x22: w(r, 569, 3); break;
          case 0x23: w(r, 68, 3); break;
          case 0x24: w(r, 566, 3); break;
          case 0x25: w(r, 1456, 2); break;
          case 0x26: w(r, 49, 2); break;
          case 0x27: w(r, 89, 2); break;
          case 0x28: w(r, 1420, 2); break;
          case 0x29: w(r, 563, 3); break;
          case 0x2a: w(r, 560, 3); break;
          case 0x2b: w(r, 66, 5); break;
          case 0x2c: w(r, 554, 3); break;
          case 0x2d: w(r, 266, 4); break;
          case 0x2e: w(r, 61, 5); break;
          case 0x2f: w(r, 416, 3); break;
          case 0x30: w(r, 1410, 2); break;
          case 0x31: w(r, 1408, 2); break;
          case 0x32: w(r, 56, 5); break;
          case 0x33: w(r, 150, 4); break;
          case 0x34: w(r, 116, 5); break;
          case 0x35: w(r, 464, 3); break;
          case 0x36: w(r, 111, 5); break;
          case 0x37: w(r, 1406, 2); break;
          case 0x38: w(r, 455, 3); break;
          case 0x39: w(r, 452, 3); break;
          case 0x3a: w(r, 449, 3); break;
          case 0x3b: w(r, 446, 3); break;
          case 0x3c: w(r, 443, 3); break;
          case 0x3d: w(r, 142, 4); break;
          case 0x3e: w(r, 437, 3); break;
          case 0x3f: w(r, 434, 2); break;
          case 0x40: w(r, 434, 3); break;
          case 0x41: w(r, 431, 3); break;
          case 0x42: w(r, 428, 3); break;
          case 0x43: w(r, 138, 4); break;
          case 0x44: w(r, 425, 3); break;
          case 0x45: w(r, 440, 3); break;
          case 0x46: w(r, 458, 3); break;
          case 0x47: w(r, 101, 5); break;
          case 0x48: w(r, 126, 4); break;
          case 0x49: w(r, 76, 2); break;
          case 0x4a: w(r, 76, 5); break;
          case 0x4b: w(r, 134, 2); break;
          case 0x4c: w(r, 134, 4); break;
          case 0x4d: w(r, 47, 4); break;
          case 0x4e: w(r, 809, 3); break;
          case 0x4f: w(r, 806, 3); break;
          case 0x50: w(r, 803, 3); break;
          case 0x51: w(r, 146, 4); break;
          case 0x52: w(r, 1436, 2); break;
          case 0x53: w(r, 797, 3); break;
          case 0x54: w(r, 154, 4); break;
          case 0x55: w(r, 1440, 2); break;
          case 0x56: w(r, 51, 5); break;
          case 0x57: w(r, 93, 3); break;
          case 0x58: w(r, 161, 1); break;
          case 0x59: w(r, 158, 1); break;
          case 0x5a: w(r, 44, 1); break;
          case 0x5b: w(r, 184, 1); break;
          case 0x5c: w(r, 188, 1); break;
          case 0x5d: w(r, 192, 1); break;
          case 0x5e: w(r, 196, 1); break;
          case 0x5f: w(r, 200, 1); break;
          case 0x60: w(r, 204, 1); break;
          case 0x61: w(r, 208, 1); break;
          case 0x62: w(r, 160, 2); break;
          case 0x63: w(r, 175, 2); break;
          case 0x64: w(r, 179, 2); break;
          case 0x65: w(r, 183, 2); break;
          case 0x66: w(r, 187, 2); break;
          case 0x67: w(r, 191, 2); break;
          case 0x68: w(r, 195, 2); break;
          case 0x69: w(r, 199, 2); break;
          case 0x6a: w(r, 203, 2); break;
          case 0x6b: w(r, 207, 2); break;
          case 0x6c: w(r, 211, 2); break;
          case 0x6d: w(r, 1084, 2); break;
          case 0x6e: w(r, 1279, 2); break;
          case 0x6f: w(r, 1286, 2); break;
          case 0x70: w(r, 1288, 2); break;
          case 0x71: w(r, 380, 3); break;
          case 0x72: w(r, 1292, 2); break;
          case 0x73: w(r, 1294, 2); break;
          case 0x74: w(r, 383, 3); break;
          case 0x75: w(r, 1322, 2); break;
          case 0x76: w(r, 1320, 2); break;
          case 0x77: w(r, 386, 2); break;
          case 0x78: w(r, 386, 3); break;
          case 0x79: w(r, 392, 3); break;
          case 0x7a: w(r, 1312, 2); break;
          case 0x80: w(r, 1310, 2); break;
          case 0x81: w(r, 1308, 2); break;
          case 0x82: w(r, 1306, 2); break;
          case 0x83: w(r, 1304, 2); break;
          case 0x84: w(r, 1302, 2); break;
          case 0x85: w(r, 1300, 2); break;
          case 0x86: w(r, 1298, 2); break;
          case 0x87: w(r, 1296, 2); break;
          case 0x88: w(r, 331, 3); break;
          case 0x89: w(r, 330, 4); break;
          case 0x8a: w(r, 1250, 2); break;
          case 0x8b: w(r, 1248, 2); break;
          case 0x8c: w(r, 1246, 2); break;
          case 0x8d: w(r, 1244, 2); break;
          case 0x8e: w(r, 1254, 2); break;
          case 0x8f: w(r, 360, 2); break;
          case 0x90: w(r, 399, 2); break;
          case 0x91: w(r, 398, 3); break;
          case 0x92: w(r, 401, 3); break;
          case 0x93: w(r, 404, 3); break;
          case 0x94: w(r, 407, 3); break;
          case 0x95: w(r, 1270, 2); break;
          case 0x96: w(r, 1268, 2); break;
          case 0x97: w(r, 1266, 2); break;
          case 0x98: w(r, 1264, 2); break;
          case 0x99: w(r, 1262, 2); break;
          case 0x9a: w(r, 1260, 2); break;
          case 0x9b: w(r, 1258, 2); break;
          case 0x9c: w(r, 410, 2); break;
          case 0x9d: w(r, 413, 2); break;
          case 0x9e: w(r, 419, 2); break;
          case 0x9f: w(r, 410, 3); break;
          case 0xa0: w(r, 413, 3); break;
          case 0xa1: w(r, 387, 2); break;
          case 0xa2: w(r, 419, 3); break;
          case 0xa3: w(r, 551, 3); break;
          case 0xa4: w(r, 557, 3); break;
          case 0xa5: w(r, 393, 2); break;
          case 0xa6: w(r, 572, 3); break;
          case 0xa7: w(r, 334, 3); break;
          case 0xa8: w(r, 334, 4); break;
          case 0xa9: w(r, 381, 2); break;
          case 0xaa: w(r, 584, 3); break;
          case 0xab: w(r, 587, 3); break;
          case 0xac: w(r, 590, 3); break;
          case 0xad: w(r, 39, 3); break;
          case 0xae: w(r, 39, 5); break;
          case 0xaf: w(r, 39, 6); break;
          case 0xb0: w(r, 1382, 2); break;
          case 0xb1: w(r, 1384, 2); break;
          case 0xb2: w(r, 1386, 2); break;
          case 0xb3: w(r, 1388, 2); break;
          case 0xb4: w(r, 1390, 2); break;
          case 0xb5: w(r, 1392, 2); break;
          case 0xb6: w(r, 1394, 2); break;
          case 0xb7: w(r, 493, 2); break;
          case 0xb8: w(r, 1396, 2); break;
          case 0xb9: w(r, 1398, 2); break;
          case 0xba: w(r, 1400, 2); break;
          case 0xbb: w(r, 1402, 2); break;
          case 0xbc: w(r, 1404, 2); break;
          case 0xbd: w(r, 1326, 2); break;
          case 0xbe: w(r, 1328, 2); break;
          case 0xbf: w(r, 1330, 2); break;
          case 0xc0: w(r, 1332, 2); break;
          case 0xc1: w(r, 1334, 2); break;
          case 0xc2: w(r, 346, 4); break;
          case 0xc3: w(r, 1336, 2); break;
          case 0xc4: w(r, 1338, 2); break;
          case 0xc5: w(r, 1340, 2); break;
          case 0xc6: w(r, 358, 4); break;
          case 0xc7: w(r, 479, 3); break;
          case 0xc8: w(r, 1342, 2); break;
          case 0xc9: w(r, 1344, 2); break;
          case 0xca: w(r, 1346, 2); break;
          case 0xcb: w(r, 1348, 2); break;
          case 0xcc: w(r, 1350, 2); break;
          case 0xcd: w(r, 1352, 2); break;
          case 0xce: w(r, 1354, 2); break;
          case 0xcf: w(r, 1356, 2); break;
          case 0xd0: w(r, 333, 2); break;
          case 0xd1: w(r, 1358, 2); break;
          case 0xd2: w(r, 503, 3); break;
          case 0xd3: w(r, 1360, 2); break;
          case 0xd4: w(r, 1362, 2); break;
          case 0xd5: w(r, 548, 3); break;
          case 0xd6: w(r, 512, 3); break;
          case 0xd7: w(r, 1744, 2); break;
          case 0xd8: w(r, 366, 4); break;
          case 0xd9: w(r, 509, 3); break;
          case 0xda: w(r, 1746, 2); break;
          case 0xdb: w(r, 1748, 2); break;
          case 0xdc: w(r, 1752, 2); break;
          case 0xdd: w(r, 1750, 2); break;
          case 0xde: w(r, 494, 3); break;
          case 0xdf: w(r, 491, 3); break;
          case 0xe0: w(r, 158, 1); break;
          case 0xe1: w(r, 44, 1); break;
          case 0xe2: w(r, 184, 1); break;
          case 0xe3: w(r, 188, 1); break;
          case 0xe4: w(r, 192, 1); break;
          case 0xe5: w(r, 196, 1); break;
          case 0xe6: w(r, 200, 1); break;
          case 0xe7: w(r, 204, 1); break;
          case 0xe8: w(r, 208, 1); break;
          case 0xe9: w(r, 160, 2); break;
          case 0xea: w(r, 175, 2); break;
          case 0xeb: w(r, 179, 2); break;
          case 0xec: w(r, 183, 2); break;
          case 0xed: w(r, 187, 2); break;
          case 0xee: w(r, 191, 2); break;
          case 0xef: w(r, 195, 2); break;
          case 0xf0: w(r, 199, 2); break;
          case 0xf1: w(r, 203, 2); break;
          case 0xf2: w(r, 207, 2); break;
          case 0xf3: w(r, 211, 2); break;
          case 0xf4: w(r, 1084, 2); break;
          case 0xf5: w(r, 1279, 2); break;
          case 0xf6: w(r, 1286, 2); break;
          case 0xf7: w(r, 1288, 2); break;
          case 0xf8: w(r, 1448, 2); break;
          case 0xf9: w(r, 1450, 2); break;
          case 0xfa: w(r, 1280, 2); break;
          case 0xfb: w(r, 1276, 2); break;
          case 0xfc: w(r, 1274, 2); break;
          case 0xfd: w(r, 1272, 2); break;
          case 0xfe: w(r, 988, 2); break;
          case 0xff: w(r, 599, 3); break;
          default: r.push_back(c);
          }
        }
        break;
        case 0xa700:
        {
          switch (static_cast<uint8_t>(c & 0xff))
          {
          case 0x70: w(r, 2165, 1); break;
          default: r.push_back(c);
          }
        }
        break;
        case 0xfb00:
        {
          switch (static_cast<uint8_t>(c & 0xff))
          {
          case 0x0: w(r, 593, 2); break;
          case 0x1: w(r, 597, 2); break;
          case 0x2: w(r, 594, 2); break;
          case 0x3: w(r, 596, 3); break;
          case 0x4: w(r, 593, 3); break;
          case 0x5: w(r, 1724, 2); break;
          case 0x6: w(r, 1724, 2); break;
          case 0x13: w(r, 1728, 2); break;
          case 0x14: w(r, 1730, 2); break;
          case 0x15: w(r, 1732, 2); break;
          case 0x16: w(r, 1734, 2); break;
          case 0x17: w(r, 1736, 2); break;
          case 0x1d: w(r, 2164, 1); break;
          case 0x1f: w(r, 2149, 1); break;
          case 0x20: w(r, 2150, 1); break;
          case 0x21: w(r, 1722, 1); break;
          case 0x22: w(r, 2151, 1); break;
          case 0x23: w(r, 2152, 1); break;
          case 0x24: w(r, 2153, 1); break;
          case 0x25: w(r, 1723, 1); break;
          case 0x26: w(r, 2154, 1); break;
          case 0x27: w(r, 2155, 1); break;
          case 0x28: w(r, 2156, 1); break;
          case 0x29: w(r, 1773, 1); break;
          case 0x2a: w(r, 2157, 1); break;
          case 0x2b: w(r, 2157, 1); break;
          case 0x2c: w(r, 2157, 1); break;
          case 0x2d: w(r, 2157, 1); break;
          case 0x2e: w(r, 1722, 1); break;
          case 0x2f: w(r, 1722, 1); break;
          case 0x30: w(r, 1722, 1); break;
          case 0x31: w(r, 2159, 1); break;
          case 0x32: w(r, 2160, 1); break;
          case 0x33: w(r, 2151, 1); break;
          case 0x34: w(r, 2152, 1); break;
          case 0x35: w(r, 2161, 1); break;
          case 0x36: w(r, 2162, 1); break;
          case 0x38: w(r, 2163, 1); break;
          case 0x39: w(r, 2164, 1); break;
          case 0x3a: w(r, 2179, 1); break;
          case 0x3b: w(r, 2153, 1); break;
          case 0x3c: w(r, 1723, 1); break;
          case 0x3e: w(r, 2180, 1); break;
          case 0x40: w(r, 2181, 1); break;
          case 0x41: w(r, 2182, 1); break;
          case 0x43: w(r, 2183, 1); break;
          case 0x44: w(r, 2184, 1); break;
          case 0x46: w(r, 2185, 1); break;
          case 0x47: w(r, 2186, 1); break;
          case 0x48: w(r, 2155, 1); break;
          case 0x49: w(r, 2157, 1); break;
          case 0x4a: w(r, 2156, 1); break;
          case 0x4b: w(r, 2161, 1); break;
          case 0x4c: w(r, 2159, 1); break;
          case 0x4d: w(r, 2153, 1); break;
          case 0x4e: w(r, 2184, 1); break;
          case 0x4f: w(r, 1722, 2); break;
          case 0x50: w(r, 2187, 1); break;
          case 0x51: w(r, 2187, 1); break;
          case 0x52: w(r, 2189, 1); break;
          case 0x53: w(r, 2189, 1); break;
          case 0x54: w(r, 2189, 1); break;
          case 0x55: w(r, 2189, 1); break;
          case 0x56: w(r, 2166, 1); break;
          case 0x57: w(r, 2166, 1); break;
          case 0x58: w(r, 2166, 1); break;
          case 0x59: w(r, 2166, 1); break;
          case 0x5a: w(r, 2167, 1); break;
          case 0x5b: w(r, 2167, 1); break;
          case 0x5c: w(r, 2167, 1); break;
          case 0x5d: w(r, 2167, 1); break;
          case 0x5e: w(r, 2169, 1); break;
          case 0x5f: w(r, 2169, 1); break;
          case 0x60: w(r, 2169, 1); break;
          case 0x61: w(r, 2169, 1); break;
          case 0x62: w(r, 2171, 1); break;
          case 0x63: w(r, 2171, 1); break;
          case 0x64: w(r, 2171, 1); break;
          case 0x65: w(r, 2171, 1); break;
          case 0x66: w(r, 2173, 1); break;
          case 0x67: w(r, 2173, 1); break;
          case 0x68: w(r, 2173, 1); break;
          case 0x69: w(r, 2173, 1); break;
          case 0x6a: w(r, 2175, 1); break;
          case 0x6b: w(r, 2175, 1); break;
          case 0x6c: w(r, 2175, 1); break;
          case 0x6d: w(r, 2175, 1); break;
          case 0x6e: w(r, 2177, 1); break;
          case 0x6f: w(r, 2177, 1); break;
          case 0x70: w(r, 2177, 1); break;
          case 0x71: w(r, 2177, 1); break;
          case 0x72: w(r, 2122, 1); break;
          case 0x73: w(r, 2122, 1); break;
          case 0x74: w(r, 2122, 1); break;
          case 0x75: w(r, 2122, 1); break;
          case 0x76: w(r, 2124, 1); break;
          case 0x77: w(r, 2124, 1); break;
          case 0x78: w(r, 2124, 1); break;
          case 0x79: w(r, 2124, 1); break;
          case 0x7a: w(r, 2126, 1); break;
          case 0x7b: w(r, 2126, 1); break;
          case 0x7c: w(r, 2126, 1); break;
          case 0x7d: w(r, 2126, 1); break;
          case 0x7e: w(r, 2128, 1); break;
          case 0x7f: w(r, 2128, 1); break;
          case 0x80: w(r, 2128, 1); break;
          case 0x81: w(r, 2128, 1); break;
          case 0x82: w(r, 2130, 1); break;
          case 0x83: w(r, 2130, 1); break;
          case 0x84: w(r, 2132, 1); break;
          case 0x85: w(r, 2132, 1); break;
          case 0x86: w(r, 2134, 1); break;
          case 0x87: w(r, 2134, 1); break;
          case 0x88: w(r, 2136, 1); break;
          case 0x89: w(r, 2136, 1); break;
          case 0x8a: w(r, 2138, 1); break;
          case 0x8b: w(r, 2138, 1); break;
          case 0x8c: w(r, 2109, 1); break;
          case 0x8d: w(r, 2109, 1); break;
          case 0x8e: w(r, 2110, 1); break;
          case 0x8f: w(r, 2110, 1); break;
          case 0x90: w(r, 2110, 1); break;
          case 0x91: w(r, 2110, 1); break;
          case 0x92: w(r, 2112, 1); break;
          case 0x93: w(r, 2112, 1); break;
          case 0x94: w(r, 2112, 1); break;
          case 0x95: w(r, 2112, 1); break;
          case 0x96: w(r, 2114, 1); break;
          case 0x97: w(r, 2114, 1); break;
          case 0x98: w(r, 2114, 1); break;
          case 0x99: w(r, 2114, 1); break;
          case 0x9a: w(r, 2116, 1); break;
          case 0x9b: w(r, 2116, 1); break;
          case 0x9c: w(r, 2116, 1); break;
          case 0x9d: w(r, 2116, 1); break;
          case 0x9e: w(r, 2118, 1); break;
          case 0x9f: w(r, 2118, 1); break;
          case 0xa0: w(r, 2120, 1); break;
          case 0xa1: w(r, 2120, 1); break;
          case 0xa2: w(r, 2120, 1); break;
          case 0xa3: w(r, 2120, 1); break;
          case 0xa4: w(r, 1709, 1); break;
          case 0xa5: w(r, 1709, 1); break;
          case 0xa6: w(r, 2036, 1); break;
          case 0xa7: w(r, 2036, 1); break;
          case 0xa8: w(r, 2036, 1); break;
          case 0xa9: w(r, 2036, 1); break;
          case 0xaa: w(r, 2141, 1); break;
          case 0xab: w(r, 2141, 1); break;
          case 0xac: w(r, 2141, 1); break;
          case 0xad: w(r, 2141, 1); break;
          case 0xae: w(r, 424, 1); break;
          case 0xaf: w(r, 424, 1); break;
          case 0xb0: w(r, 424, 1); break;
          case 0xb1: w(r, 424, 1); break;
          case 0xd3: w(r, 2143, 1); break;
          case 0xd4: w(r, 2143, 1); break;
          case 0xd5: w(r, 2143, 1); break;
          case 0xd6: w(r, 2143, 1); break;
          case 0xd7: w(r, 1701, 1); break;
          case 0xd8: w(r, 1701, 1); break;
          case 0xd9: w(r, 1697, 1); break;
          case 0xda: w(r, 1697, 1); break;
          case 0xdb: w(r, 1693, 1); break;
          case 0xdc: w(r, 1693, 1); break;
          case 0xdd: w(r, 1720, 2); break;
          case 0xde: w(r, 2145, 1); break;
          case 0xdf: w(r, 2145, 1); break;
          case 0xe0: w(r, 2147, 1); break;
          case 0xe1: w(r, 2147, 1); break;
          case 0xe2: w(r, 2140, 1); break;
          case 0xe3: w(r, 2140, 1); break;
          case 0xe4: w(r, 1689, 1); break;
          case 0xe5: w(r, 1689, 1); break;
          case 0xe6: w(r, 1689, 1); break;
          case 0xe7: w(r, 1689, 1); break;
          case 0xe8: w(r, 2, 1); break;
          case 0xe9: w(r, 2, 1); break;
          case 0xea: w(r, 1712, 2); break;
          case 0xeb: w(r, 1712, 2); break;
          case 0xec: w(r, 1708, 2); break;
          case 0xed: w(r, 1708, 2); break;
          case 0xee: w(r, 1704, 2); break;
          case 0xef: w(r, 1704, 2); break;
          case 0xf0: w(r, 1700, 2); break;
          case 0xf1: w(r, 1700, 2); break;
          case 0xf2: w(r, 1696, 2); break;
          case 0xf3: w(r, 1696, 2); break;
          case 0xf4: w(r, 1692, 2); break;
          case 0xf5: w(r, 1692, 2); break;
          case 0xf6: w(r, 1688, 2); break;
          case 0xf7: w(r, 1688, 2); break;
          case 0xf8: w(r, 1688, 2); break;
          case 0xf9: w(r, 1548, 2); break;
          case 0xfa: w(r, 1548, 2); break;
          case 0xfb: w(r, 1548, 2); break;
          case 0xfc: w(r, 339, 1); break;
          case 0xfd: w(r, 339, 1); break;
          case 0xfe: w(r, 339, 1); break;
          case 0xff: w(r, 339, 1); break;
          default: r.push_back(c);
          }
        }
        break;
        case 0xfc00:
        {
          switch (static_cast<uint8_t>(c & 0xff))
          {
          case 0x0: w(r, 532, 2); break;
          case 0x1: w(r, 686, 2); break;
          case 0x2: w(r, 629, 2); break;
          case 0x3: w(r, 1548, 2); break;
          case 0x4: w(r, 628, 2); break;
          case 0x5: w(r, 1562, 2); break;
          case 0x6: w(r, 800, 2); break;
          case 0x7: w(r, 626, 2); break;
          case 0x8: w(r, 1474, 2); break;
          case 0x9: w(r, 1538, 2); break;
          case 0xa: w(r, 1536, 2); break;
          case 0xb: w(r, 620, 2); break;
          case 0xc: w(r, 971, 2); break;
          case 0xd: w(r, 614, 2); break;
          case 0xe: w(r, 539, 2); break;
          case 0xf: w(r, 1528, 2); break;
          case 0x10: w(r, 1526, 2); break;
          case 0x11: w(r, 1684, 2); break;
          case 0x12: w(r, 1486, 2); break;
          case 0x13: w(r, 1518, 2); break;
          case 0x14: w(r, 1516, 2); break;
          case 0x15: w(r, 522, 2); break;
          case 0x16: w(r, 396, 2); break;
          case 0x17: w(r, 525, 2); break;
          case 0x18: w(r, 355, 2); break;
          case 0x19: w(r, 669, 2); break;
          case 0x1a: w(r, 1682, 2); break;
          case 0x1b: w(r, 664, 2); break;
          case 0x1c: w(r, 476, 2); break;
          case 0x1d: w(r, 524, 2); break;
          case 0x1e: w(r, 470, 2); break;
          case 0x1f: w(r, 374, 2); break;
          case 0x20: w(r, 728, 2); break;
          case 0x21: w(r, 473, 2); break;
          case 0x22: w(r, 1470, 2); break;
          case 0x23: w(r, 695, 2); break;
          case 0x24: w(r, 746, 2); break;
          case 0x25: w(r, 1468, 2); break;
          case 0x26: w(r, 1466, 2); break;
          case 0x27: w(r, 857, 2); break;
          case 0x28: w(r, 1464, 2); break;
          case 0x29: w(r, 395, 2); break;
          case 0x2a: w(r, 352, 2); break;
          case 0x2b: w(r, 1462, 2); break;
          case 0x2c: w(r, 845, 2); break;
          case 0x2d: w(r, 1494, 2); break;
          case 0x2e: w(r, 1496, 2); break;
          case 0x2f: w(r, 839, 2); break;
          case 0x30: w(r, 794, 2); break;
          case 0x31: w(r, 1564, 2); break;
          case 0x32: w(r, 1566, 2); break;
          case 0x33: w(r, 1498, 2); break;
          case 0x34: w(r, 698, 2); break;
          case 0x35: w(r, 1568, 2); break;
          case 0x36: w(r, 1570, 2); break;
          case 0x37: w(r, 1572, 2); break;
          case 0x38: w(r, 1500, 2); break;
          case 0x39: w(r, 1502, 2); break;
          case 0x3a: w(r, 1492, 2); break;
          case 0x3b: w(r, 1490, 2); break;
          case 0x3c: w(r, 713, 2); break;
          case 0x3d: w(r, 1574, 2); break;
          case 0x3e: w(r, 1576, 2); break;
          case 0x3f: w(r, 692, 2); break;
          case 0x40: w(r, 707, 2); break;
          case 0x41: w(r, 818, 2); break;
          case 0x42: w(r, 16, 2); break;
          case 0x43: w(r, 1, 2); break;
          case 0x44: w(r, 10, 2); break;
          case 0x45: w(r, 17, 2); break;
          case 0x46: w(r, 354, 2); break;
          case 0x47: w(r, 540, 2); break;
          case 0x48: w(r, 353, 2); break;
          case 0x49: w(r, 528, 2); break;
          case 0x4a: w(r, 531, 2); break;
          case 0x4b: w(r, 467, 2); break;
          case 0x4c: w(r, 650, 2); break;
          case 0x4d: w(r, 1488, 2); break;
          case 0x4e: w(r, 635, 2); break;
          case 0x4f: w(r, 1558, 2); break;
          case 0x50: w(r, 1560, 2); break;
          case 0x51: w(r, 1666, 2); break;
          case 0x52: w(r, 656, 2); break;
          case 0x53: w(r, 1542, 2); break;
          case 0x54: w(r, 1544, 2); break;
          case 0x55: w(r, 532, 2); break;
          case 0x56: w(r, 686, 2); break;
          case 0x57: w(r, 1546, 2); break;
          case 0x58: w(r, 629, 2); break;
          case 0x59: w(r, 1548, 2); break;
          case 0x5a: w(r, 628, 2); break;
          case 0x5b: w(r, 1796, 1); break;
          case 0x5c: w(r, 338, 1); break;
          case 0x5d: w(r, 2, 1); break;
          case 0x5e: w(r, 3, 1); break;
          case 0x5f: w(r, 3, 1); break;
          case 0x60: w(r, 3, 1); break;
          case 0x61: w(r, 3, 1); break;
          case 0x62: w(r, 3, 1); break;
          case 0x63: w(r, 3, 1); break;
          case 0x64: w(r, 1550, 2); break;
          case 0x65: w(r, 1552, 2); break;
          case 0x66: w(r, 629, 2); break;
          case 0x67: w(r, 640, 2); break;
          case 0x68: w(r, 1548, 2); break;
          case 0x69: w(r, 628, 2); break;
          case 0x6a: w(r, 364, 2); break;
          case 0x6b: w(r, 1554, 2); break;
          case 0x6c: w(r, 1474, 2); break;
          case 0x6d: w(r, 1540, 2); break;
          case 0x6e: w(r, 1538, 2); break;
          case 0x6f: w(r, 1536, 2); break;
          case 0x70: w(r, 1534, 2); break;
          case 0x71: w(r, 1532, 2); break;
          case 0x72: w(r, 539, 2); break;
          case 0x73: w(r, 1530, 2); break;
          case 0x74: w(r, 1528, 2); break;
          case 0x75: w(r, 1526, 2); break;
          case 0x76: w(r, 1524, 2); break;
          case 0x77: w(r, 1522, 2); break;
          case 0x78: w(r, 1486, 2); break;
          case 0x79: w(r, 1520, 2); break;
          case 0x7a: w(r, 1518, 2); break;
          case 0x7b: w(r, 1516, 2); break;
          case 0x7c: w(r, 1564, 2); break;
          case 0x7d: w(r, 1566, 2); break;
          case 0x7e: w(r, 1568, 2); break;
          case 0x7f: w(r, 1570, 2); break;
          case 0x80: w(r, 1572, 2); break;
          case 0x81: w(r, 1490, 2); break;
          case 0x82: w(r, 713, 2); break;
          case 0x83: w(r, 1574, 2); break;
          case 0x84: w(r, 1576, 2); break;
          case 0x85: w(r, 16, 2); break;
          case 0x86: w(r, 1, 2); break;
          case 0x87: w(r, 10, 2); break;
          case 0x88: w(r, 1578, 2); break;
          case 0x89: w(r, 353, 2); break;
          case 0x8a: w(r, 1580, 2); break;
          case 0x8b: w(r, 1582, 2); break;
          case 0x8c: w(r, 635, 2); break;
          case 0x8d: w(r, 1556, 2); break;
          case 0x8e: w(r, 1558, 2); break;
          case 0x8f: w(r, 1560, 2); break;
          case 0x90: w(r, 2, 1); break;
          case 0x91: w(r, 1550, 2); break;
          case 0x92: w(r, 1552, 2); break;
          case 0x93: w(r, 629, 2); break;
          case 0x94: w(r, 640, 2); break;
          case 0x95: w(r, 1548, 2); break;
          case 0x96: w(r, 628, 2); break;
          case 0x97: w(r, 532, 2); break;
          case 0x98: w(r, 686, 2); break;
          case 0x99: w(r, 1546, 2); break;
          case 0x9a: w(r, 629, 2); break;
          case 0x9b: w(r, 11, 2); break;
          case 0x9c: w(r, 1562, 2); break;
          case 0x9d: w(r, 800, 2); break;
          case 0x9e: w(r, 626, 2); break;
          case 0x9f: w(r, 1474, 2); break;
          case 0xa0: w(r, 1476, 2); break;
          case 0xa1: w(r, 620, 2); break;
          case 0xa2: w(r, 971, 2); break;
          case 0xa3: w(r, 614, 2); break;
          case 0xa4: w(r, 539, 2); break;
          case 0xa5: w(r, 1484, 2); break;
          case 0xa6: w(r, 1486, 2); break;
          case 0xa7: w(r, 522, 2); break;
          case 0xa8: w(r, 396, 2); break;
          case 0xa9: w(r, 525, 2); break;
          case 0xaa: w(r, 355, 2); break;
          case 0xab: w(r, 669, 2); break;
          case 0xac: w(r, 664, 2); break;
          case 0xad: w(r, 476, 2); break;
          case 0xae: w(r, 524, 2); break;
          case 0xaf: w(r, 470, 2); break;
          case 0xb0: w(r, 374, 2); break;
          case 0xb1: w(r, 728, 2); break;
          case 0xb2: w(r, 1472, 2); break;
          case 0xb3: w(r, 473, 2); break;
          case 0xb4: w(r, 1470, 2); break;
          case 0xb5: w(r, 695, 2); break;
          case 0xb6: w(r, 746, 2); break;
          case 0xb7: w(r, 1468, 2); break;
          case 0xb8: w(r, 1466, 2); break;
          case 0xb9: w(r, 1464, 2); break;
          case 0xba: w(r, 395, 2); break;
          case 0xbb: w(r, 352, 2); break;
          case 0xbc: w(r, 1462, 2); break;
          case 0xbd: w(r, 845, 2); break;
          case 0xbe: w(r, 1494, 2); break;
          case 0xbf: w(r, 1496, 2); break;
          case 0xc0: w(r, 839, 2); break;
          case 0xc1: w(r, 794, 2); break;
          case 0xc2: w(r, 1498, 2); break;
          case 0xc3: w(r, 698, 2); break;
          case 0xc4: w(r, 1500, 2); break;
          case 0xc5: w(r, 1502, 2); break;
          case 0xc6: w(r, 1492, 2); break;
          case 0xc7: w(r, 1490, 2); break;
          case 0xc8: w(r, 713, 2); break;
          case 0xc9: w(r, 692, 2); break;
          case 0xca: w(r, 707, 2); break;
          case 0xcb: w(r, 818, 2); break;
          case 0xcc: w(r, 16, 2); break;
          case 0xcd: w(r, 6, 2); break;
          case 0xce: w(r, 17, 2); break;
          case 0xcf: w(r, 354, 2); break;
          case 0xd0: w(r, 540, 2); break;
          case 0xd1: w(r, 353, 2); break;
          case 0xd2: w(r, 467, 2); break;
          case 0xd3: w(r, 650, 2); break;
          case 0xd4: w(r, 1488, 2); break;
          case 0xd5: w(r, 635, 2); break;
          case 0xd6: w(r, 1541, 2); break;
          case 0xd7: w(r, 1666, 2); break;
          case 0xd8: w(r, 656, 2); break;
          case 0xd9: w(r, 7, 1); break;
          case 0xda: w(r, 532, 2); break;
          case 0xdb: w(r, 686, 2); break;
          case 0xdc: w(r, 1546, 2); break;
          case 0xdd: w(r, 629, 2); break;
          case 0xde: w(r, 11, 2); break;
          case 0xdf: w(r, 629, 2); break;
          case 0xe0: w(r, 11, 2); break;
          case 0xe1: w(r, 1474, 2); break;
          case 0xe2: w(r, 1476, 2); break;
          case 0xe3: w(r, 539, 2); break;
          case 0xe4: w(r, 1484, 2); break;
          case 0xe5: w(r, 1486, 2); break;
          case 0xe6: w(r, 1668, 2); break;
          case 0xe7: w(r, 374, 2); break;
          case 0xe8: w(r, 1650, 2); break;
          case 0xe9: w(r, 758, 2); break;
          case 0xea: w(r, 1652, 2); break;
          case 0xeb: w(r, 1490, 2); break;
          case 0xec: w(r, 713, 2); break;
          case 0xed: w(r, 16, 2); break;
          case 0xee: w(r, 635, 2); break;
          case 0xef: w(r, 1541, 2); break;
          case 0xf0: w(r, 629, 2); break;
          case 0xf1: w(r, 11, 2); break;
          case 0xf2: w(r, 1793, 1); break;
          case 0xf3: w(r, 1793, 1); break;
          case 0xf4: w(r, 1793, 1); break;
          case 0xf5: w(r, 1664, 2); break;
          case 0xf6: w(r, 1662, 2); break;
          case 0xf7: w(r, 1660, 2); break;
          case 0xf8: w(r, 1658, 2); break;
          case 0xf9: w(r, 1656, 2); break;
          case 0xfa: w(r, 1674, 2); break;
          case 0xfb: w(r, 1604, 2); break;
          case 0xfc: w(r, 1606, 2); break;
          case 0xfd: w(r, 1608, 2); break;
          case 0xfe: w(r, 1610, 2); break;
          case 0xff: w(r, 651, 2); break;
          default: r.push_back(c);
          }
        }
        break;
        case 0xfd00:
        {
          switch (static_cast<uint8_t>(c & 0xff))
          {
          case 0x0: w(r, 675, 2); break;
          case 0x1: w(r, 477, 2); break;
          case 0x2: w(r, 468, 2); break;
          case 0x3: w(r, 615, 2); break;
          case 0x4: w(r, 471, 2); break;
          case 0x5: w(r, 1596, 2); break;
          case 0x6: w(r, 1594, 2); break;
          case 0x7: w(r, 1592, 2); break;
          case 0x8: w(r, 1590, 2); break;
          case 0x9: w(r, 770, 2); break;
          case 0xa: w(r, 725, 2); break;
          case 0xb: w(r, 1588, 2); break;
          case 0xc: w(r, 758, 2); break;
          case 0xd: w(r, 1586, 2); break;
          case 0xe: w(r, 1584, 2); break;
          case 0xf: w(r, 1646, 2); break;
          case 0x10: w(r, 1648, 2); break;
          case 0x11: w(r, 1664, 2); break;
          case 0x12: w(r, 1662, 2); break;
          case 0x13: w(r, 1660, 2); break;
          case 0x14: w(r, 1658, 2); break;
          case 0x15: w(r, 1656, 2); break;
          case 0x16: w(r, 1674, 2); break;
          case 0x17: w(r, 1604, 2); break;
          case 0x18: w(r, 1606, 2); break;
          case 0x19: w(r, 1608, 2); break;
          case 0x1a: w(r, 1610, 2); break;
          case 0x1b: w(r, 651, 2); break;
          case 0x1c: w(r, 675, 2); break;
          case 0x1d: w(r, 477, 2); break;
          case 0x1e: w(r, 468, 2); break;
          case 0x1f: w(r, 615, 2); break;
          case 0x20: w(r, 471, 2); break;
          case 0x21: w(r, 1596, 2); break;
          case 0x22: w(r, 1594, 2); break;
          case 0x23: w(r, 1592, 2); break;
          case 0x24: w(r, 1590, 2); break;
          case 0x25: w(r, 770, 2); break;
          case 0x26: w(r, 725, 2); break;
          case 0x27: w(r, 1588, 2); break;
          case 0x28: w(r, 758, 2); break;
          case 0x29: w(r, 1586, 2); break;
          case 0x2a: w(r, 1584, 2); break;
          case 0x2b: w(r, 1646, 2); break;
          case 0x2c: w(r, 1648, 2); break;
          case 0x2d: w(r, 770, 2); break;
          case 0x2e: w(r, 725, 2); break;
          case 0x2f: w(r, 1588, 2); break;
          case 0x30: w(r, 758, 2); break;
          case 0x31: w(r, 1650, 2); break;
          case 0x32: w(r, 1652, 2); break;
          case 0x33: w(r, 857, 2); break;
          case 0x34: w(r, 476, 2); break;
          case 0x35: w(r, 524, 2); break;
          case 0x36: w(r, 470, 2); break;
          case 0x37: w(r, 770, 2); break;
          case 0x38: w(r, 725, 2); break;
          case 0x39: w(r, 1588, 2); break;
          case 0x3a: w(r, 857, 2); break;
          case 0x3b: w(r, 1464, 2); break;
          case 0x3c: w(r, 4, 1); break;
          case 0x3d: w(r, 4, 1); break;
          case 0x50: w(r, 1025, 3); break;
          case 0x51: w(r, 1019, 3); break;
          case 0x52: w(r, 1019, 3); break;
          case 0x53: w(r, 971, 3); break;
          case 0x54: w(r, 1205, 3); break;
          case 0x55: w(r, 545, 3); break;
          case 0x56: w(r, 542, 3); break;
          case 0x57: w(r, 539, 3); break;
          case 0x58: w(r, 533, 3); break;
          case 0x59: w(r, 533, 3); break;
          case 0x5a: w(r, 530, 3); break;
          case 0x5b: w(r, 527, 3); break;
          case 0x5c: w(r, 524, 3); break;
          case 0x5d: w(r, 521, 3); break;
          case 0x5e: w(r, 476, 3); break;
          case 0x5f: w(r, 374, 3); break;
          case 0x60: w(r, 374, 3); break;
          case 0x61: w(r, 377, 3); break;
          case 0x62: w(r, 785, 3); break;
          case 0x63: w(r, 785, 3); break;
          case 0x64: w(r, 779, 3); break;
          case 0x65: w(r, 779, 3); break;
          case 0x66: w(r, 473, 3); break;
          case 0x67: w(r, 773, 3); break;
          case 0x68: w(r, 773, 3); break;
          case 0x69: w(r, 770, 3); break;
          case 0x6a: w(r, 764, 3); break;
          case 0x6b: w(r, 764, 3); break;
          case 0x6c: w(r, 758, 3); break;
          case 0x6d: w(r, 758, 3); break;
          case 0x6e: w(r, 752, 3); break;
          case 0x6f: w(r, 746, 3); break;
          case 0x70: w(r, 746, 3); break;
          case 0x71: w(r, 863, 3); break;
          case 0x72: w(r, 863, 3); break;
          case 0x73: w(r, 860, 3); break;
          case 0x74: w(r, 857, 3); break;
          case 0x75: w(r, 395, 3); break;
          case 0x76: w(r, 352, 3); break;
          case 0x77: w(r, 352, 3); break;
          case 0x78: w(r, 854, 3); break;
          case 0x79: w(r, 851, 3); break;
          case 0x7a: w(r, 848, 3); break;
          case 0x7b: w(r, 845, 3); break;
          case 0x7c: w(r, 839, 3); break;
          case 0x7d: w(r, 839, 3); break;
          case 0x7e: w(r, 704, 3); break;
          case 0x7f: w(r, 836, 3); break;
          case 0x80: w(r, 707, 3); break;
          case 0x81: w(r, 833, 3); break;
          case 0x82: w(r, 830, 3); break;
          case 0x83: w(r, 824, 3); break;
          case 0x84: w(r, 824, 3); break;
          case 0x85: w(r, 818, 3); break;
          case 0x86: w(r, 818, 3); break;
          case 0x87: w(r, 812, 3); break;
          case 0x88: w(r, 812, 3); break;
          case 0x89: w(r, 534, 3); break;
          case 0x8a: w(r, 354, 3); break;
          case 0x8b: w(r, 674, 3); break;
          case 0x8c: w(r, 671, 3); break;
          case 0x8d: w(r, 660, 3); break;
          case 0x8e: w(r, 668, 3); break;
          case 0x8f: w(r, 665, 3); break;
          case 0x92: w(r, 662, 3); break;
          case 0x93: w(r, 659, 3); break;
          case 0x94: w(r, 656, 3); break;
          case 0x95: w(r, 653, 3); break;
          case 0x96: w(r, 650, 3); break;
          case 0x97: w(r, 644, 3); break;
          case 0x98: w(r, 644, 3); break;
          case 0x99: w(r, 641, 3); break;
          case 0x9a: w(r, 638, 3); break;
          case 0x9b: w(r, 635, 3); break;
          case 0x9c: w(r, 629, 3); break;
          case 0x9d: w(r, 629, 3); break;
          case 0x9e: w(r, 626, 3); break;
          case 0x9f: w(r, 623, 3); break;
          case 0xa0: w(r, 620, 3); break;
          case 0xa1: w(r, 617, 3); break;
          case 0xa2: w(r, 614, 3); break;
          case 0xa3: w(r, 611, 3); break;
          case 0xa4: w(r, 743, 3); break;
          case 0xa5: w(r, 740, 3); break;
          case 0xa6: w(r, 737, 3); break;
          case 0xa7: w(r, 734, 3); break;
          case 0xa8: w(r, 731, 3); break;
          case 0xa9: w(r, 728, 3); break;
          case 0xaa: w(r, 725, 3); break;
          case 0xab: w(r, 695, 3); break;
          case 0xac: w(r, 692, 3); break;
          case 0xad: w(r, 689, 3); break;
          case 0xae: w(r, 686, 3); break;
          case 0xaf: w(r, 683, 3); break;
          case 0xb0: w(r, 680, 3); break;
          case 0xb1: w(r, 630, 3); break;
          case 0xb2: w(r, 698, 3); break;
          case 0xb3: w(r, 701, 3); break;
          case 0xb4: w(r, 704, 3); break;
          case 0xb5: w(r, 707, 3); break;
          case 0xb6: w(r, 710, 3); break;
          case 0xb7: w(r, 713, 3); break;
          case 0xb8: w(r, 677, 3); break;
          case 0xb9: w(r, 716, 3); break;
          case 0xba: w(r, 719, 3); break;
          case 0xbb: w(r, 722, 3); break;
          case 0xbc: w(r, 719, 3); break;
          case 0xbd: w(r, 677, 3); break;
          case 0xbe: w(r, 678, 3); break;
          case 0xbf: w(r, 755, 3); break;
          case 0xc0: w(r, 791, 3); break;
          case 0xc1: w(r, 794, 3); break;
          case 0xc2: w(r, 800, 3); break;
          case 0xc3: w(r, 722, 3); break;
          case 0xc4: w(r, 395, 3); break;
          case 0xc5: w(r, 473, 3); break;
          case 0xc6: w(r, 470, 3); break;
          case 0xc7: w(r, 467, 3); break;
          case 0xf0: w(r, 461, 3); break;
          case 0xf1: w(r, 422, 3); break;
          case 0xf2: w(r, 4, 4); break;
          case 0xf3: w(r, 362, 4); break;
          case 0xf4: w(r, 354, 4); break;
          case 0xf5: w(r, 350, 4); break;
          case 0xf6: w(r, 342, 4); break;
          case 0xf7: w(r, 9, 4); break;
          case 0xf8: w(r, 14, 4); break;
          case 0xf9: w(r, 0, 3); break;
          case 0xfa: w(r, 0, 18); break;
          case 0xfb: w(r, 18, 8); break;
          case 0xfc: w(r, 338, 4); break;
          default: r.push_back(c);
          }
        }
        break;
        case 0xfe00:
        {
          switch (static_cast<uint8_t>(c & 0xff))
          {
          case 0x10: w(r, 1603, 1); break;
          case 0x11: w(r, 1768, 1); break;
          case 0x12: w(r, 1792, 1); break;
          case 0x13: w(r, 1112, 1); break;
          case 0x14: w(r, 1767, 1); break;
          case 0x15: w(r, 1424, 1); break;
          case 0x16: w(r, 1425, 1); break;
          case 0x17: w(r, 1803, 1); break;
          case 0x18: w(r, 1802, 1); break;
          case 0x19: w(r, 389, 3); break;
          case 0x30: w(r, 389, 2); break;
          case 0x31: w(r, 1765, 1); break;
          case 0x32: w(r, 1764, 1); break;
          case 0x33: w(r, 1763, 1); break;
          case 0x34: w(r, 1763, 1); break;
          case 0x35: w(r, 26, 1); break;
          case 0x36: w(r, 32, 1); break;
          case 0x37: w(r, 1762, 1); break;
          case 0x38: w(r, 1769, 1); break;
          case 0x39: w(r, 1160, 1); break;
          case 0x3a: w(r, 1162, 1); break;
          case 0x3b: w(r, 1788, 1); break;
          case 0x3c: w(r, 1787, 1); break;
          case 0x3d: w(r, 1786, 1); break;
          case 0x3e: w(r, 1785, 1); break;
          case 0x3f: w(r, 1784, 1); break;
          case 0x40: w(r, 1783, 1); break;
          case 0x41: w(r, 1782, 1); break;
          case 0x42: w(r, 1781, 1); break;
          case 0x43: w(r, 1780, 1); break;
          case 0x44: w(r, 1779, 1); break;
          case 0x47: w(r, 1756, 1); break;
          case 0x48: w(r, 1757, 1); break;
          case 0x49: w(r, 3, 1); break;
          case 0x4a: w(r, 3, 1); break;
          case 0x4b: w(r, 3, 1); break;
          case 0x4c: w(r, 3, 1); break;
          case 0x4d: w(r, 1763, 1); break;
          case 0x4e: w(r, 1763, 1); break;
          case 0x4f: w(r, 1763, 1); break;
          case 0x50: w(r, 1603, 1); break;
          case 0x51: w(r, 1768, 1); break;
          case 0x52: w(r, 347, 1); break;
          case 0x54: w(r, 1767, 1); break;
          case 0x55: w(r, 1112, 1); break;
          case 0x56: w(r, 1425, 1); break;
          case 0x57: w(r, 1424, 1); break;
          case 0x58: w(r, 1765, 1); break;
          case 0x59: w(r, 26, 1); break;
          case 0x5a: w(r, 32, 1); break;
          case 0x5b: w(r, 1762, 1); break;
          case 0x5c: w(r, 1769, 1); break;
          case 0x5d: w(r, 1160, 1); break;
          case 0x5e: w(r, 1162, 1); break;
          case 0x5f: w(r, 1770, 1); break;
          case 0x60: w(r, 1771, 1); break;
          case 0x61: w(r, 1772, 1); break;
          case 0x62: w(r, 1773, 1); break;
          case 0x63: w(r, 1774, 1); break;
          case 0x64: w(r, 1775, 1); break;
          case 0x65: w(r, 1776, 1); break;
          case 0x66: w(r, 1109, 1); break;
          case 0x68: w(r, 1754, 1); break;
          case 0x69: w(r, 1804, 1); break;
          case 0x6a: w(r, 1800, 1); break;
          case 0x6b: w(r, 1766, 1); break;
          case 0x70: w(r, 3, 1); break;
          case 0x71: w(r, 1793, 1); break;
          case 0x72: w(r, 3, 1); break;
          case 0x74: w(r, 3, 1); break;
          case 0x76: w(r, 3, 1); break;
          case 0x77: w(r, 1793, 1); break;
          case 0x78: w(r, 3, 1); break;
          case 0x79: w(r, 1793, 1); break;
          case 0x7a: w(r, 3, 1); break;
          case 0x7b: w(r, 1793, 1); break;
          case 0x7c: w(r, 3, 1); break;
          case 0x7d: w(r, 1793, 1); break;
          case 0x7e: w(r, 3, 1); break;
          case 0x7f: w(r, 1793, 1); break;
          case 0x80: w(r, 1795, 1); break;
          case 0x81: w(r, 4, 1); break;
          case 0x82: w(r, 4, 1); break;
          case 0x83: w(r, 4, 1); break;
          case 0x84: w(r, 4, 1); break;
          case 0x85: w(r, 14, 1); break;
          case 0x86: w(r, 14, 1); break;
          case 0x87: w(r, 4, 1); break;
          case 0x88: w(r, 4, 1); break;
          case 0x89: w(r, 11, 1); break;
          case 0x8a: w(r, 11, 1); break;
          case 0x8b: w(r, 11, 1); break;
          case 0x8c: w(r, 11, 1); break;
          case 0x8d: w(r, 4, 1); break;
          case 0x8e: w(r, 4, 1); break;
          case 0x8f: w(r, 364, 1); break;
          case 0x90: w(r, 364, 1); break;
          case 0x91: w(r, 364, 1); break;
          case 0x92: w(r, 364, 1); break;
          case 0x93: w(r, 1798, 1); break;
          case 0x94: w(r, 1798, 1); break;
          case 0x95: w(r, 539, 1); break;
          case 0x96: w(r, 539, 1); break;
          case 0x97: w(r, 539, 1); break;
          case 0x98: w(r, 539, 1); break;
          case 0x99: w(r, 1486, 1); break;
          case 0x9a: w(r, 1486, 1); break;
          case 0x9b: w(r, 1486, 1); break;
          case 0x9c: w(r, 1486, 1); break;
          case 0x9d: w(r, 18, 1); break;
          case 0x9e: w(r, 18, 1); break;
          case 0x9f: w(r, 18, 1); break;
          case 0xa0: w(r, 18, 1); break;
          case 0xa1: w(r, 355, 1); break;
          case 0xa2: w(r, 355, 1); break;
          case 0xa3: w(r, 355, 1); break;
          case 0xa4: w(r, 355, 1); break;
          case 0xa5: w(r, 471, 1); break;
          case 0xa6: w(r, 471, 1); break;
          case 0xa7: w(r, 471, 1); break;
          case 0xa8: w(r, 471, 1); break;
          case 0xa9: w(r, 357, 1); break;
          case 0xaa: w(r, 357, 1); break;
          case 0xab: w(r, 1796, 1); break;
          case 0xac: w(r, 1796, 1); break;
          case 0xad: w(r, 338, 1); break;
          case 0xae: w(r, 338, 1); break;
          case 0xaf: w(r, 1523, 1); break;
          case 0xb0: w(r, 1523, 1); break;
          case 0xb1: w(r, 15, 1); break;
          case 0xb2: w(r, 15, 1); break;
          case 0xb3: w(r, 15, 1); break;
          case 0xb4: w(r, 15, 1); break;
          case 0xb5: w(r, 725, 1); break;
          case 0xb6: w(r, 725, 1); break;
          case 0xb7: w(r, 725, 1); break;
          case 0xb8: w(r, 725, 1); break;
          case 0xb9: w(r, 0, 1); break;
          case 0xba: w(r, 0, 1); break;
          case 0xbb: w(r, 0, 1); break;
          case 0xbc: w(r, 0, 1); break;
          case 0xbd: w(r, 695, 1); break;
          case 0xbe: w(r, 695, 1); break;
          case 0xbf: w(r, 695, 1); break;
          case 0xc0: w(r, 695, 1); break;
          case 0xc1: w(r, 857, 1); break;
          case 0xc2: w(r, 857, 1); break;
          case 0xc3: w(r, 857, 1); break;
          case 0xc4: w(r, 857, 1); break;
          case 0xc5: w(r, 1464, 1); break;
          case 0xc6: w(r, 1464, 1); break;
          case 0xc7: w(r, 1464, 1); break;
          case 0xc8: w(r, 1464, 1); break;
          case 0xc9: w(r, 9, 1); break;
          case 0xca: w(r, 9, 1); break;
          case 0xcb: w(r, 9, 1); break;
          case 0xcc: w(r, 9, 1); break;
          case 0xcd: w(r, 845, 1); break;
          case 0xce: w(r, 845, 1); break;
          case 0xcf: w(r, 845, 1); break;
          case 0xd0: w(r, 845, 1); break;
          case 0xd1: w(r, 794, 1); break;
          case 0xd2: w(r, 794, 1); break;
          case 0xd3: w(r, 794, 1); break;
          case 0xd4: w(r, 794, 1); break;
          case 0xd5: w(r, 422, 1); break;
          case 0xd6: w(r, 422, 1); break;
          case 0xd7: w(r, 422, 1); break;
          case 0xd8: w(r, 422, 1); break;
          case 0xd9: w(r, 363, 1); break;
          case 0xda: w(r, 363, 1); break;
          case 0xdb: w(r, 363, 1); break;
          case 0xdc: w(r, 363, 1); break;
          case 0xdd: w(r, 1, 1); break;
          case 0xde: w(r, 1, 1); break;
          case 0xdf: w(r, 1, 1); break;
          case 0xe0: w(r, 1, 1); break;
          case 0xe1: w(r, 17, 1); break;
          case 0xe2: w(r, 17, 1); break;
          case 0xe3: w(r, 17, 1); break;
          case 0xe4: w(r, 17, 1); break;
          case 0xe5: w(r, 467, 1); break;
          case 0xe6: w(r, 467, 1); break;
          case 0xe7: w(r, 467, 1); break;
          case 0xe8: w(r, 467, 1); break;
          case 0xe9: w(r, 7, 1); break;
          case 0xea: w(r, 7, 1); break;
          case 0xeb: w(r, 7, 1); break;
          case 0xec: w(r, 7, 1); break;
          case 0xed: w(r, 14, 1); break;
          case 0xee: w(r, 14, 1); break;
          case 0xef: w(r, 2, 1); break;
          case 0xf0: w(r, 2, 1); break;
          case 0xf1: w(r, 11, 1); break;
          case 0xf2: w(r, 11, 1); break;
          case 0xf3: w(r, 11, 1); break;
          case 0xf4: w(r, 11, 1); break;
          case 0xf5: w(r, 22, 2); break;
          case 0xf6: w(r, 22, 2); break;
          case 0xf7: w(r, 22, 2); break;
          case 0xf8: w(r, 22, 2); break;
          case 0xf9: w(r, 22, 2); break;
          case 0xfa: w(r, 22, 2); break;
          case 0xfb: w(r, 22, 2); break;
          case 0xfc: w(r, 22, 2); break;
          default: r.push_back(c);
          }
        }
        break;
        case 0xff00:
        {
          switch (static_cast<uint8_t>(c & 0xff))
          {
          case 0x1: w(r, 1424, 1); break;
          case 0x2: w(r, 1806, 1); break;
          case 0x3: w(r, 1770, 1); break;
          case 0x4: w(r, 1804, 1); break;
          case 0x5: w(r, 1800, 1); break;
          case 0x6: w(r, 1771, 1); break;
          case 0x7: w(r, 1801, 1); break;
          case 0x8: w(r, 26, 1); break;
          case 0x9: w(r, 32, 1); break;
          case 0xa: w(r, 1772, 1); break;
          case 0xb: w(r, 1773, 1); break;
          case 0xc: w(r, 1603, 1); break;
          case 0xd: w(r, 1774, 1); break;
          case 0xe: w(r, 347, 1); break;
          case 0xf: w(r, 957, 1); break;
          case 0x10: w(r, 161, 1); break;
          case 0x11: w(r, 158, 1); break;
          case 0x12: w(r, 44, 1); break;
          case 0x13: w(r, 184, 1); break;
          case 0x14: w(r, 188, 1); break;
          case 0x15: w(r, 192, 1); break;
          case 0x16: w(r, 196, 1); break;
          case 0x17: w(r, 200, 1); break;
          case 0x18: w(r, 204, 1); break;
          case 0x19: w(r, 208, 1); break;
          case 0x1a: w(r, 1112, 1); break;
          case 0x1b: w(r, 1767, 1); break;
          case 0x1c: w(r, 1775, 1); break;
          case 0x1d: w(r, 1109, 1); break;
          case 0x1e: w(r, 1776, 1); break;
          case 0x1f: w(r, 1425, 1); break;
          case 0x20: w(r, 1766, 1); break;
          case 0x21: w(r, 491, 1); break;
          case 0x22: w(r, 912, 1); break;
          case 0x23: w(r, 358, 1); break;
          case 0x24: w(r, 517, 1); break;
          case 0x25: w(r, 921, 1); break;
          case 0x26: w(r, 924, 1); break;
          case 0x27: w(r, 404, 1); break;
          case 0x28: w(r, 399, 1); break;
          case 0x29: w(r, 163, 1); break;
          case 0x2a: w(r, 936, 1); break;
          case 0x2b: w(r, 939, 1); break;
          case 0x2c: w(r, 515, 1); break;
          case 0x2d: w(r, 401, 1); break;
          case 0x2e: w(r, 1122, 1); break;
          case 0x2f: w(r, 1125, 1); break;
          case 0x30: w(r, 381, 1); break;
          case 0x31: w(r, 1131, 1); break;
          case 0x32: w(r, 1134, 1); break;
          case 0x33: w(r, 1137, 1); break;
          case 0x34: w(r, 407, 1); break;
          case 0x35: w(r, 1143, 1); break;
          case 0x36: w(r, 162, 1); break;
          case 0x37: w(r, 1149, 1); break;
          case 0x38: w(r, 869, 1); break;
          case 0x39: w(r, 1155, 1); break;
          case 0x3a: w(r, 1158, 1); break;
          case 0x3b: w(r, 1756, 1); break;
          case 0x3c: w(r, 1754, 1); break;
          case 0x3d: w(r, 1757, 1); break;
          case 0x3e: w(r, 1755, 1); break;
          case 0x3f: w(r, 1763, 1); break;
          case 0x40: w(r, 1761, 1); break;
          case 0x41: w(r, 40, 1); break;
          case 0x42: w(r, 383, 1); break;
          case 0x43: w(r, 331, 1); break;
          case 0x44: w(r, 41, 1); break;
          case 0x45: w(r, 518, 1); break;
          case 0x46: w(r, 593, 1); break;
          case 0x47: w(r, 361, 1); break;
          case 0x48: w(r, 380, 1); break;
          case 0x49: w(r, 167, 1); break;
          case 0x4a: w(r, 1047, 1); break;
          case 0x4b: w(r, 330, 1); break;
          case 0x4c: w(r, 333, 1); break;
          case 0x4d: w(r, 334, 1); break;
          case 0x4e: w(r, 1059, 1); break;
          case 0x4f: w(r, 480, 1); break;
          case 0x50: w(r, 366, 1); break;
          case 0x51: w(r, 1071, 1); break;
          case 0x52: w(r, 39, 1); break;
          case 0x53: w(r, 43, 1); break;
          case 0x54: w(r, 1089, 1); break;
          case 0x55: w(r, 967, 1); break;
          case 0x56: w(r, 166, 1); break;
          case 0x57: w(r, 1098, 1); break;
          case 0x58: w(r, 872, 1); break;
          case 0x59: w(r, 1104, 1); break;
          case 0x5a: w(r, 400, 1); break;
          case 0x5b: w(r, 1762, 1); break;
          case 0x5c: w(r, 1777, 1); break;
          case 0x5d: w(r, 1769, 1); break;
          case 0x5e: w(r, 1789, 1); break;
          case 0x5f: w(r, 1790, 1); break;
          case 0x60: w(r, 1791, 1); break;
          case 0x61: w(r, 1792, 1); break;
          case 0x62: w(r, 1782, 1); break;
          case 0x63: w(r, 1781, 1); break;
          case 0x64: w(r, 1768, 1); break;
          case 0x65: w(r, 1778, 1); break;
          case 0x66: w(r, 1758, 1); break;
          case 0x67: w(r, 57, 1); break;
          case 0x68: w(r, 151, 1); break;
          case 0x69: w(r, 1759, 1); break;
          case 0x6a: w(r, 119, 1); break;
          case 0x6b: w(r, 498, 1); break;
          case 0x6c: w(r, 1760, 1); break;
          case 0x6d: w(r, 247, 1); break;
          case 0x6e: w(r, 104, 1); break;
          case 0x6f: w(r, 59, 1); break;
          case 0x70: w(r, 48, 1); break;
          case 0x71: w(r, 62, 1); break;
          case 0x72: w(r, 84, 1); break;
          case 0x73: w(r, 497, 1); break;
          case 0x74: w(r, 106, 1); break;
          case 0x75: w(r, 485, 1); break;
          case 0x76: w(r, 135, 1); break;
          case 0x77: w(r, 45, 1); break;
          case 0x78: w(r, 81, 1); break;
          case 0x79: w(r, 54, 1); break;
          case 0x7a: w(r, 575, 1); break;
          case 0x7b: w(r, 71, 1); break;
          case 0x7c: w(r, 103, 1); break;
          case 0x7d: w(r, 63, 1); break;
          case 0x7e: w(r, 68, 1); break;
          case 0x7f: w(r, 1407, 1); break;
          case 0x80: w(r, 113, 1); break;
          case 0x81: w(r, 73, 1); break;
          case 0x82: w(r, 454, 1); break;
          case 0x83: w(r, 1456, 1); break;
          case 0x84: w(r, 49, 1); break;
          case 0x85: w(r, 580, 1); break;
          case 0x86: w(r, 231, 1); break;
          case 0x87: w(r, 1877, 1); break;
          case 0x88: w(r, 257, 1); break;
          case 0x89: w(r, 563, 1); break;
          case 0x8a: w(r, 66, 1); break;
          case 0x8b: w(r, 61, 1); break;
          case 0x8c: w(r, 56, 1); break;
          case 0x8d: w(r, 111, 1); break;
          case 0x8e: w(r, 142, 1); break;
          case 0x8f: w(r, 101, 1); break;
          case 0x90: w(r, 76, 1); break;
          case 0x91: w(r, 75, 1); break;
          case 0x92: w(r, 47, 1); break;
          case 0x93: w(r, 1879, 1); break;
          case 0x94: w(r, 806, 1); break;
          case 0x95: w(r, 803, 1); break;
          case 0x96: w(r, 1878, 1); break;
          case 0x97: w(r, 58, 1); break;
          case 0x98: w(r, 77, 1); break;
          case 0x99: w(r, 50, 1); break;
          case 0x9a: w(r, 51, 1); break;
          case 0x9b: w(r, 46, 1); break;
          case 0x9c: w(r, 93, 1); break;
          case 0x9d: w(r, 52, 1); break;
          case 0xa0: w(r, 1869, 1); break;
          case 0xa1: w(r, 124, 1); break;
          case 0xa2: w(r, 1868, 1); break;
          case 0xa3: w(r, 1867, 1); break;
          case 0xa4: w(r, 323, 1); break;
          case 0xa5: w(r, 1866, 1); break;
          case 0xa6: w(r, 1865, 1); break;
          case 0xa7: w(r, 319, 1); break;
          case 0xa8: w(r, 1864, 1); break;
          case 0xa9: w(r, 315, 1); break;
          case 0xaa: w(r, 1863, 1); break;
          case 0xab: w(r, 1862, 1); break;
          case 0xac: w(r, 1861, 1); break;
          case 0xad: w(r, 1860, 1); break;
          case 0xae: w(r, 1876, 1); break;
          case 0xaf: w(r, 1875, 1); break;
          case 0xb0: w(r, 1874, 1); break;
          case 0xb1: w(r, 311, 1); break;
          case 0xb2: w(r, 307, 1); break;
          case 0xb3: w(r, 1873, 1); break;
          case 0xb4: w(r, 1872, 1); break;
          case 0xb5: w(r, 303, 1); break;
          case 0xb6: w(r, 1871, 1); break;
          case 0xb7: w(r, 27, 1); break;
          case 0xb8: w(r, 29, 1); break;
          case 0xb9: w(r, 1870, 1); break;
          case 0xba: w(r, 121, 1); break;
          case 0xbb: w(r, 287, 1); break;
          case 0xbc: w(r, 283, 1); break;
          case 0xbd: w(r, 279, 1); break;
          case 0xbe: w(r, 36, 1); break;
          case 0xc2: w(r, 122, 1); break;
          case 0xc3: w(r, 1901, 1); break;
          case 0xc4: w(r, 1900, 1); break;
          case 0xc5: w(r, 1899, 1); break;
          case 0xc6: w(r, 30, 1); break;
          case 0xc7: w(r, 1898, 1); break;
          case 0xca: w(r, 1897, 1); break;
          case 0xcb: w(r, 1896, 1); break;
          case 0xcc: w(r, 28, 1); break;
          case 0xcd: w(r, 1895, 1); break;
          case 0xce: w(r, 1894, 1); break;
          case 0xcf: w(r, 1893, 1); break;
          case 0xd2: w(r, 1892, 1); break;
          case 0xd3: w(r, 37, 1); break;
          case 0xd4: w(r, 1891, 1); break;
          case 0xd5: w(r, 1890, 1); break;
          case 0xd6: w(r, 1889, 1); break;
          case 0xd7: w(r, 1888, 1); break;
          case 0xda: w(r, 1887, 1); break;
          case 0xdb: w(r, 217, 1); break;
          case 0xdc: w(r, 1917, 1); break;
          case 0xe0: w(r, 1916, 1); break;
          case 0xe1: w(r, 1915, 1); break;
          case 0xe2: w(r, 1914, 1); break;
          case 0xe3: w(r, 3, 1); break;
          case 0xe4: w(r, 1913, 1); break;
          case 0xe5: w(r, 1912, 1); break;
          case 0xe6: w(r, 1911, 1); break;
          case 0xe8: w(r, 1910, 1); break;
          case 0xe9: w(r, 1909, 1); break;
          case 0xea: w(r, 1908, 1); break;
          case 0xeb: w(r, 1907, 1); break;
          case 0xec: w(r, 1906, 1); break;
          case 0xed: w(r, 1905, 1); break;
          case 0xee: w(r, 1904, 1); break;
          default: r.push_back(c);
          }
        }
        break;
        default: r.push_back(c);
        }
      }
      break;
      case 0x10000:
      {
        switch (static_cast<uint16_t>(c & 0x0000ff00))
        {
        case 0x1000:
        {
          switch (static_cast<uint8_t>(c & 0xff))
          {
          case 0x9a: w(r, 1903, 1); break;
          case 0x9c: w(r, 1902, 1); break;
          case 0xab: w(r, 1886, 1); break;
          default: r.push_back(c);
          }
        }
        break;
        case 0xd100:
        {
          switch (static_cast<uint8_t>(c & 0xff))
          {
          case 0x5e: w(r, 1885, 1); break;
          case 0x5f: w(r, 1883, 1); break;
          case 0x60: w(r, 1883, 1); break;
          case 0x61: w(r, 1883, 1); break;
          case 0x62: w(r, 1883, 1); break;
          case 0x63: w(r, 1883, 1); break;
          case 0x64: w(r, 1883, 1); break;
          case 0xbb: w(r, 1881, 1); break;
          case 0xbc: w(r, 1880, 1); break;
          case 0xbd: w(r, 1881, 1); break;
          case 0xbe: w(r, 1880, 1); break;
          case 0xbf: w(r, 1881, 1); break;
          case 0xc0: w(r, 1880, 1); break;
          default: r.push_back(c);
          }
        }
        break;
        case 0xd400:
        {
          switch (static_cast<uint8_t>(c & 0xff))
          {
          case 0x0: w(r, 491, 1); break;
          case 0x1: w(r, 912, 1); break;
          case 0x2: w(r, 358, 1); break;
          case 0x3: w(r, 517, 1); break;
          case 0x4: w(r, 921, 1); break;
          case 0x5: w(r, 924, 1); break;
          case 0x6: w(r, 404, 1); break;
          case 0x7: w(r, 399, 1); break;
          case 0x8: w(r, 163, 1); break;
          case 0x9: w(r, 936, 1); break;
          case 0xa: w(r, 939, 1); break;
          case 0xb: w(r, 515, 1); break;
          case 0xc: w(r, 401, 1); break;
          case 0xd: w(r, 1122, 1); break;
          case 0xe: w(r, 1125, 1); break;
          case 0xf: w(r, 381, 1); break;
          case 0x10: w(r, 1131, 1); break;
          case 0x11: w(r, 1134, 1); break;
          case 0x12: w(r, 1137, 1); break;
          case 0x13: w(r, 407, 1); break;
          case 0x14: w(r, 1143, 1); break;
          case 0x15: w(r, 162, 1); break;
          case 0x16: w(r, 1149, 1); break;
          case 0x17: w(r, 869, 1); break;
          case 0x18: w(r, 1155, 1); break;
          case 0x19: w(r, 1158, 1); break;
          case 0x1a: w(r, 40, 1); break;
          case 0x1b: w(r, 383, 1); break;
          case 0x1c: w(r, 331, 1); break;
          case 0x1d: w(r, 41, 1); break;
          case 0x1e: w(r, 518, 1); break;
          case 0x1f: w(r, 593, 1); break;
          case 0x20: w(r, 361, 1); break;
          case 0x21: w(r, 380, 1); break;
          case 0x22: w(r, 167, 1); break;
          case 0x23: w(r, 1047, 1); break;
          case 0x24: w(r, 330, 1); break;
          case 0x25: w(r, 333, 1); break;
          case 0x26: w(r, 334, 1); break;
          case 0x27: w(r, 1059, 1); break;
          case 0x28: w(r, 480, 1); break;
          case 0x29: w(r, 366, 1); break;
          case 0x2a: w(r, 1071, 1); break;
          case 0x2b: w(r, 39, 1); break;
          case 0x2c: w(r, 43, 1); break;
          case 0x2d: w(r, 1089, 1); break;
          case 0x2e: w(r, 967, 1); break;
          case 0x2f: w(r, 166, 1); break;
          case 0x30: w(r, 1098, 1); break;
          case 0x31: w(r, 872, 1); break;
          case 0x32: w(r, 1104, 1); break;
          case 0x33: w(r, 400, 1); break;
          case 0x34: w(r, 491, 1); break;
          case 0x35: w(r, 912, 1); break;
          case 0x36: w(r, 358, 1); break;
          case 0x37: w(r, 517, 1); break;
          case 0x38: w(r, 921, 1); break;
          case 0x39: w(r, 924, 1); break;
          case 0x3a: w(r, 404, 1); break;
          case 0x3b: w(r, 399, 1); break;
          case 0x3c: w(r, 163, 1); break;
          case 0x3d: w(r, 936, 1); break;
          case 0x3e: w(r, 939, 1); break;
          case 0x3f: w(r, 515, 1); break;
          case 0x40: w(r, 401, 1); break;
          case 0x41: w(r, 1122, 1); break;
          case 0x42: w(r, 1125, 1); break;
          case 0x43: w(r, 381, 1); break;
          case 0x44: w(r, 1131, 1); break;
          case 0x45: w(r, 1134, 1); break;
          case 0x46: w(r, 1137, 1); break;
          case 0x47: w(r, 407, 1); break;
          case 0x48: w(r, 1143, 1); break;
          case 0x49: w(r, 162, 1); break;
          case 0x4a: w(r, 1149, 1); break;
          case 0x4b: w(r, 869, 1); break;
          case 0x4c: w(r, 1155, 1); break;
          case 0x4d: w(r, 1158, 1); break;
          case 0x4e: w(r, 40, 1); break;
          case 0x4f: w(r, 383, 1); break;
          case 0x50: w(r, 331, 1); break;
          case 0x51: w(r, 41, 1); break;
          case 0x52: w(r, 518, 1); break;
          case 0x53: w(r, 593, 1); break;
          case 0x54: w(r, 361, 1); break;
          case 0x56: w(r, 167, 1); break;
          case 0x57: w(r, 1047, 1); break;
          case 0x58: w(r, 330, 1); break;
          case 0x59: w(r, 333, 1); break;
          case 0x5a: w(r, 334, 1); break;
          case 0x5b: w(r, 1059, 1); break;
          case 0x5c: w(r, 480, 1); break;
          case 0x5d: w(r, 366, 1); break;
          case 0x5e: w(r, 1071, 1); break;
          case 0x5f: w(r, 39, 1); break;
          case 0x60: w(r, 43, 1); break;
          case 0x61: w(r, 1089, 1); break;
          case 0x62: w(r, 967, 1); break;
          case 0x63: w(r, 166, 1); break;
          case 0x64: w(r, 1098, 1); break;
          case 0x65: w(r, 872, 1); break;
          case 0x66: w(r, 1104, 1); break;
          case 0x67: w(r, 400, 1); break;
          case 0x68: w(r, 491, 1); break;
          case 0x69: w(r, 912, 1); break;
          case 0x6a: w(r, 358, 1); break;
          case 0x6b: w(r, 517, 1); break;
          case 0x6c: w(r, 921, 1); break;
          case 0x6d: w(r, 924, 1); break;
          case 0x6e: w(r, 404, 1); break;
          case 0x6f: w(r, 399, 1); break;
          case 0x70: w(r, 163, 1); break;
          case 0x71: w(r, 936, 1); break;
          case 0x72: w(r, 939, 1); break;
          case 0x73: w(r, 515, 1); break;
          case 0x74: w(r, 401, 1); break;
          case 0x75: w(r, 1122, 1); break;
          case 0x76: w(r, 1125, 1); break;
          case 0x77: w(r, 381, 1); break;
          case 0x78: w(r, 1131, 1); break;
          case 0x79: w(r, 1134, 1); break;
          case 0x7a: w(r, 1137, 1); break;
          case 0x7b: w(r, 407, 1); break;
          case 0x7c: w(r, 1143, 1); break;
          case 0x7d: w(r, 162, 1); break;
          case 0x7e: w(r, 1149, 1); break;
          case 0x7f: w(r, 869, 1); break;
          case 0x80: w(r, 1155, 1); break;
          case 0x81: w(r, 1158, 1); break;
          case 0x82: w(r, 40, 1); break;
          case 0x83: w(r, 383, 1); break;
          case 0x84: w(r, 331, 1); break;
          case 0x85: w(r, 41, 1); break;
          case 0x86: w(r, 518, 1); break;
          case 0x87: w(r, 593, 1); break;
          case 0x88: w(r, 361, 1); break;
          case 0x89: w(r, 380, 1); break;
          case 0x8a: w(r, 167, 1); break;
          case 0x8b: w(r, 1047, 1); break;
          case 0x8c: w(r, 330, 1); break;
          case 0x8d: w(r, 333, 1); break;
          case 0x8e: w(r, 334, 1); break;
          case 0x8f: w(r, 1059, 1); break;
          case 0x90: w(r, 480, 1); break;
          case 0x91: w(r, 366, 1); break;
          case 0x92: w(r, 1071, 1); break;
          case 0x93: w(r, 39, 1); break;
          case 0x94: w(r, 43, 1); break;
          case 0x95: w(r, 1089, 1); break;
          case 0x96: w(r, 967, 1); break;
          case 0x97: w(r, 166, 1); break;
          case 0x98: w(r, 1098, 1); break;
          case 0x99: w(r, 872, 1); break;
          case 0x9a: w(r, 1104, 1); break;
          case 0x9b: w(r, 400, 1); break;
          case 0x9c: w(r, 491, 1); break;
          case 0x9e: w(r, 358, 1); break;
          case 0x9f: w(r, 517, 1); break;
          case 0xa2: w(r, 404, 1); break;
          case 0xa5: w(r, 936, 1); break;
          case 0xa6: w(r, 939, 1); break;
          case 0xa9: w(r, 1122, 1); break;
          case 0xaa: w(r, 1125, 1); break;
          case 0xab: w(r, 381, 1); break;
          case 0xac: w(r, 1131, 1); break;
          case 0xae: w(r, 1137, 1); break;
          case 0xaf: w(r, 407, 1); break;
          case 0xb0: w(r, 1143, 1); break;
          case 0xb1: w(r, 162, 1); break;
          case 0xb2: w(r, 1149, 1); break;
          case 0xb3: w(r, 869, 1); break;
          case 0xb4: w(r, 1155, 1); break;
          case 0xb5: w(r, 1158, 1); break;
          case 0xb6: w(r, 40, 1); break;
          case 0xb7: w(r, 383, 1); break;
          case 0xb8: w(r, 331, 1); break;
          case 0xb9: w(r, 41, 1); break;
          case 0xbb: w(r, 593, 1); break;
          case 0xbd: w(r, 380, 1); break;
          case 0xbe: w(r, 167, 1); break;
          case 0xbf: w(r, 1047, 1); break;
          case 0xc0: w(r, 330, 1); break;
          case 0xc1: w(r, 333, 1); break;
          case 0xc2: w(r, 334, 1); break;
          case 0xc3: w(r, 1059, 1); break;
          case 0xc5: w(r, 366, 1); break;
          case 0xc6: w(r, 1071, 1); break;
          case 0xc7: w(r, 39, 1); break;
          case 0xc8: w(r, 43, 1); break;
          case 0xc9: w(r, 1089, 1); break;
          case 0xca: w(r, 967, 1); break;
          case 0xcb: w(r, 166, 1); break;
          case 0xcc: w(r, 1098, 1); break;
          case 0xcd: w(r, 872, 1); break;
          case 0xce: w(r, 1104, 1); break;
          case 0xcf: w(r, 400, 1); break;
          case 0xd0: w(r, 491, 1); break;
          case 0xd1: w(r, 912, 1); break;
          case 0xd2: w(r, 358, 1); break;
          case 0xd3: w(r, 517, 1); break;
          case 0xd4: w(r, 921, 1); break;
          case 0xd5: w(r, 924, 1); break;
          case 0xd6: w(r, 404, 1); break;
          case 0xd7: w(r, 399, 1); break;
          case 0xd8: w(r, 163, 1); break;
          case 0xd9: w(r, 936, 1); break;
          case 0xda: w(r, 939, 1); break;
          case 0xdb: w(r, 515, 1); break;
          case 0xdc: w(r, 401, 1); break;
          case 0xdd: w(r, 1122, 1); break;
          case 0xde: w(r, 1125, 1); break;
          case 0xdf: w(r, 381, 1); break;
          case 0xe0: w(r, 1131, 1); break;
          case 0xe1: w(r, 1134, 1); break;
          case 0xe2: w(r, 1137, 1); break;
          case 0xe3: w(r, 407, 1); break;
          case 0xe4: w(r, 1143, 1); break;
          case 0xe5: w(r, 162, 1); break;
          case 0xe6: w(r, 1149, 1); break;
          case 0xe7: w(r, 869, 1); break;
          case 0xe8: w(r, 1155, 1); break;
          case 0xe9: w(r, 1158, 1); break;
          case 0xea: w(r, 40, 1); break;
          case 0xeb: w(r, 383, 1); break;
          case 0xec: w(r, 331, 1); break;
          case 0xed: w(r, 41, 1); break;
          case 0xee: w(r, 518, 1); break;
          case 0xef: w(r, 593, 1); break;
          case 0xf0: w(r, 361, 1); break;
          case 0xf1: w(r, 380, 1); break;
          case 0xf2: w(r, 167, 1); break;
          case 0xf3: w(r, 1047, 1); break;
          case 0xf4: w(r, 330, 1); break;
          case 0xf5: w(r, 333, 1); break;
          case 0xf6: w(r, 334, 1); break;
          case 0xf7: w(r, 1059, 1); break;
          case 0xf8: w(r, 480, 1); break;
          case 0xf9: w(r, 366, 1); break;
          case 0xfa: w(r, 1071, 1); break;
          case 0xfb: w(r, 39, 1); break;
          case 0xfc: w(r, 43, 1); break;
          case 0xfd: w(r, 1089, 1); break;
          case 0xfe: w(r, 967, 1); break;
          case 0xff: w(r, 166, 1); break;
          default: r.push_back(c);
          }
        }
        break;
        case 0xd500:
        {
          switch (static_cast<uint8_t>(c & 0xff))
          {
          case 0x0: w(r, 1098, 1); break;
          case 0x1: w(r, 872, 1); break;
          case 0x2: w(r, 1104, 1); break;
          case 0x3: w(r, 400, 1); break;
          case 0x4: w(r, 491, 1); break;
          case 0x5: w(r, 912, 1); break;
          case 0x7: w(r, 517, 1); break;
          case 0x8: w(r, 921, 1); break;
          case 0x9: w(r, 924, 1); break;
          case 0xa: w(r, 404, 1); break;
          case 0xd: w(r, 936, 1); break;
          case 0xe: w(r, 939, 1); break;
          case 0xf: w(r, 515, 1); break;
          case 0x10: w(r, 401, 1); break;
          case 0x11: w(r, 1122, 1); break;
          case 0x12: w(r, 1125, 1); break;
          case 0x13: w(r, 381, 1); break;
          case 0x14: w(r, 1131, 1); break;
          case 0x16: w(r, 1137, 1); break;
          case 0x17: w(r, 407, 1); break;
          case 0x18: w(r, 1143, 1); break;
          case 0x19: w(r, 162, 1); break;
          case 0x1a: w(r, 1149, 1); break;
          case 0x1b: w(r, 869, 1); break;
          case 0x1c: w(r, 1155, 1); break;
          case 0x1e: w(r, 40, 1); break;
          case 0x1f: w(r, 383, 1); break;
          case 0x20: w(r, 331, 1); break;
          case 0x21: w(r, 41, 1); break;
          case 0x22: w(r, 518, 1); break;
          case 0x23: w(r, 593, 1); break;
          case 0x24: w(r, 361, 1); break;
          case 0x25: w(r, 380, 1); break;
          case 0x26: w(r, 167, 1); break;
          case 0x27: w(r, 1047, 1); break;
          case 0x28: w(r, 330, 1); break;
          case 0x29: w(r, 333, 1); break;
          case 0x2a: w(r, 334, 1); break;
          case 0x2b: w(r, 1059, 1); break;
          case 0x2c: w(r, 480, 1); break;
          case 0x2d: w(r, 366, 1); break;
          case 0x2e: w(r, 1071, 1); break;
          case 0x2f: w(r, 39, 1); break;
          case 0x30: w(r, 43, 1); break;
          case 0x31: w(r, 1089, 1); break;
          case 0x32: w(r, 967, 1); break;
          case 0x33: w(r, 166, 1); break;
          case 0x34: w(r, 1098, 1); break;
          case 0x35: w(r, 872, 1); break;
          case 0x36: w(r, 1104, 1); break;
          case 0x37: w(r, 400, 1); break;
          case 0x38: w(r, 491, 1); break;
          case 0x39: w(r, 912, 1); break;
          case 0x3b: w(r, 517, 1); break;
          case 0x3c: w(r, 921, 1); break;
          case 0x3d: w(r, 924, 1); break;
          case 0x3e: w(r, 404, 1); break;
          case 0x40: w(r, 163, 1); break;
          case 0x41: w(r, 936, 1); break;
          case 0x42: w(r, 939, 1); break;
          case 0x43: w(r, 515, 1); break;
          case 0x44: w(r, 401, 1); break;
          case 0x46: w(r, 1125, 1); break;
          case 0x4a: w(r, 1137, 1); break;
          case 0x4b: w(r, 407, 1); break;
          case 0x4c: w(r, 1143, 1); break;
          case 0x4d: w(r, 162, 1); break;
          case 0x4e: w(r, 1149, 1); break;
          case 0x4f: w(r, 869, 1); break;
          case 0x50: w(r, 1155, 1); break;
          case 0x52: w(r, 40, 1); break;
          case 0x53: w(r, 383, 1); break;
          case 0x54: w(r, 331, 1); break;
          case 0x55: w(r, 41, 1); break;
          case 0x56: w(r, 518, 1); break;
          case 0x57: w(r, 593, 1); break;
          case 0x58: w(r, 361, 1); break;
          case 0x59: w(r, 380, 1); break;
          case 0x5a: w(r, 167, 1); break;
          case 0x5b: w(r, 1047, 1); break;
          case 0x5c: w(r, 330, 1); break;
          case 0x5d: w(r, 333, 1); break;
          case 0x5e: w(r, 334, 1); break;
          case 0x5f: w(r, 1059, 1); break;
          case 0x60: w(r, 480, 1); break;
          case 0x61: w(r, 366, 1); break;
          case 0x62: w(r, 1071, 1); break;
          case 0x63: w(r, 39, 1); break;
          case 0x64: w(r, 43, 1); break;
          case 0x65: w(r, 1089, 1); break;
          case 0x66: w(r, 967, 1); break;
          case 0x67: w(r, 166, 1); break;
          case 0x68: w(r, 1098, 1); break;
          case 0x69: w(r, 872, 1); break;
          case 0x6a: w(r, 1104, 1); break;
          case 0x6b: w(r, 400, 1); break;
          case 0x6c: w(r, 491, 1); break;
          case 0x6d: w(r, 912, 1); break;
          case 0x6e: w(r, 358, 1); break;
          case 0x6f: w(r, 517, 1); break;
          case 0x70: w(r, 921, 1); break;
          case 0x71: w(r, 924, 1); break;
          case 0x72: w(r, 404, 1); break;
          case 0x73: w(r, 399, 1); break;
          case 0x74: w(r, 163, 1); break;
          case 0x75: w(r, 936, 1); break;
          case 0x76: w(r, 939, 1); break;
          case 0x77: w(r, 515, 1); break;
          case 0x78: w(r, 401, 1); break;
          case 0x79: w(r, 1122, 1); break;
          case 0x7a: w(r, 1125, 1); break;
          case 0x7b: w(r, 381, 1); break;
          case 0x7c: w(r, 1131, 1); break;
          case 0x7d: w(r, 1134, 1); break;
          case 0x7e: w(r, 1137, 1); break;
          case 0x7f: w(r, 407, 1); break;
          case 0x80: w(r, 1143, 1); break;
          case 0x81: w(r, 162, 1); break;
          case 0x82: w(r, 1149, 1); break;
          case 0x83: w(r, 869, 1); break;
          case 0x84: w(r, 1155, 1); break;
          case 0x85: w(r, 1158, 1); break;
          case 0x86: w(r, 40, 1); break;
          case 0x87: w(r, 383, 1); break;
          case 0x88: w(r, 331, 1); break;
          case 0x89: w(r, 41, 1); break;
          case 0x8a: w(r, 518, 1); break;
          case 0x8b: w(r, 593, 1); break;
          case 0x8c: w(r, 361, 1); break;
          case 0x8d: w(r, 380, 1); break;
          case 0x8e: w(r, 167, 1); break;
          case 0x8f: w(r, 1047, 1); break;
          case 0x90: w(r, 330, 1); break;
          case 0x91: w(r, 333, 1); break;
          case 0x92: w(r, 334, 1); break;
          case 0x93: w(r, 1059, 1); break;
          case 0x94: w(r, 480, 1); break;
          case 0x95: w(r, 366, 1); break;
          case 0x96: w(r, 1071, 1); break;
          case 0x97: w(r, 39, 1); break;
          case 0x98: w(r, 43, 1); break;
          case 0x99: w(r, 1089, 1); break;
          case 0x9a: w(r, 967, 1); break;
          case 0x9b: w(r, 166, 1); break;
          case 0x9c: w(r, 1098, 1); break;
          case 0x9d: w(r, 872, 1); break;
          case 0x9e: w(r, 1104, 1); break;
          case 0x9f: w(r, 400, 1); break;
          case 0xa0: w(r, 491, 1); break;
          case 0xa1: w(r, 912, 1); break;
          case 0xa2: w(r, 358, 1); break;
          case 0xa3: w(r, 517, 1); break;
          case 0xa4: w(r, 921, 1); break;
          case 0xa5: w(r, 924, 1); break;
          case 0xa6: w(r, 404, 1); break;
          case 0xa7: w(r, 399, 1); break;
          case 0xa8: w(r, 163, 1); break;
          case 0xa9: w(r, 936, 1); break;
          case 0xaa: w(r, 939, 1); break;
          case 0xab: w(r, 515, 1); break;
          case 0xac: w(r, 401, 1); break;
          case 0xad: w(r, 1122, 1); break;
          case 0xae: w(r, 1125, 1); break;
          case 0xaf: w(r, 381, 1); break;
          case 0xb0: w(r, 1131, 1); break;
          case 0xb1: w(r, 1134, 1); break;
          case 0xb2: w(r, 1137, 1); break;
          case 0xb3: w(r, 407, 1); break;
          case 0xb4: w(r, 1143, 1); break;
          case 0xb5: w(r, 162, 1); break;
          case 0xb6: w(r, 1149, 1); break;
          case 0xb7: w(r, 869, 1); break;
          case 0xb8: w(r, 1155, 1); break;
          case 0xb9: w(r, 1158, 1); break;
          case 0xba: w(r, 40, 1); break;
          case 0xbb: w(r, 383, 1); break;
          case 0xbc: w(r, 331, 1); break;
          case 0xbd: w(r, 41, 1); break;
          case 0xbe: w(r, 518, 1); break;
          case 0xbf: w(r, 593, 1); break;
          case 0xc0: w(r, 361, 1); break;
          case 0xc1: w(r, 380, 1); break;
          case 0xc2: w(r, 167, 1); break;
          case 0xc3: w(r, 1047, 1); break;
          case 0xc4: w(r, 330, 1); break;
          case 0xc5: w(r, 333, 1); break;
          case 0xc6: w(r, 334, 1); break;
          case 0xc7: w(r, 1059, 1); break;
          case 0xc8: w(r, 480, 1); break;
          case 0xc9: w(r, 366, 1); break;
          case 0xca: w(r, 1071, 1); break;
          case 0xcb: w(r, 39, 1); break;
          case 0xcc: w(r, 43, 1); break;
          case 0xcd: w(r, 1089, 1); break;
          case 0xce: w(r, 967, 1); break;
          case 0xcf: w(r, 166, 1); break;
          case 0xd0: w(r, 1098, 1); break;
          case 0xd1: w(r, 872, 1); break;
          case 0xd2: w(r, 1104, 1); break;
          case 0xd3: w(r, 400, 1); break;
          case 0xd4: w(r, 491, 1); break;
          case 0xd5: w(r, 912, 1); break;
          case 0xd6: w(r, 358, 1); break;
          case 0xd7: w(r, 517, 1); break;
          case 0xd8: w(r, 921, 1); break;
          case 0xd9: w(r, 924, 1); break;
          case 0xda: w(r, 404, 1); break;
          case 0xdb: w(r, 399, 1); break;
          case 0xdc: w(r, 163, 1); break;
          case 0xdd: w(r, 936, 1); break;
          case 0xde: w(r, 939, 1); break;
          case 0xdf: w(r, 515, 1); break;
          case 0xe0: w(r, 401, 1); break;
          case 0xe1: w(r, 1122, 1); break;
          case 0xe2: w(r, 1125, 1); break;
          case 0xe3: w(r, 381, 1); break;
          case 0xe4: w(r, 1131, 1); break;
          case 0xe5: w(r, 1134, 1); break;
          case 0xe6: w(r, 1137, 1); break;
          case 0xe7: w(r, 407, 1); break;
          case 0xe8: w(r, 1143, 1); break;
          case 0xe9: w(r, 162, 1); break;
          case 0xea: w(r, 1149, 1); break;
          case 0xeb: w(r, 869, 1); break;
          case 0xec: w(r, 1155, 1); break;
          case 0xed: w(r, 1158, 1); break;
          case 0xee: w(r, 40, 1); break;
          case 0xef: w(r, 383, 1); break;
          case 0xf0: w(r, 331, 1); break;
          case 0xf1: w(r, 41, 1); break;
          case 0xf2: w(r, 518, 1); break;
          case 0xf3: w(r, 593, 1); break;
          case 0xf4: w(r, 361, 1); break;
          case 0xf5: w(r, 380, 1); break;
          case 0xf6: w(r, 167, 1); break;
          case 0xf7: w(r, 1047, 1); break;
          case 0xf8: w(r, 330, 1); break;
          case 0xf9: w(r, 333, 1); break;
          case 0xfa: w(r, 334, 1); break;
          case 0xfb: w(r, 1059, 1); break;
          case 0xfc: w(r, 480, 1); break;
          case 0xfd: w(r, 366, 1); break;
          case 0xfe: w(r, 1071, 1); break;
          case 0xff: w(r, 39, 1); break;
          default: r.push_back(c);
          }
        }
        break;
        case 0xd600:
        {
          switch (static_cast<uint8_t>(c & 0xff))
          {
          case 0x0: w(r, 43, 1); break;
          case 0x1: w(r, 1089, 1); break;
          case 0x2: w(r, 967, 1); break;
          case 0x3: w(r, 166, 1); break;
          case 0x4: w(r, 1098, 1); break;
          case 0x5: w(r, 872, 1); break;
          case 0x6: w(r, 1104, 1); break;
          case 0x7: w(r, 400, 1); break;
          case 0x8: w(r, 491, 1); break;
          case 0x9: w(r, 912, 1); break;
          case 0xa: w(r, 358, 1); break;
          case 0xb: w(r, 517, 1); break;
          case 0xc: w(r, 921, 1); break;
          case 0xd: w(r, 924, 1); break;
          case 0xe: w(r, 404, 1); break;
          case 0xf: w(r, 399, 1); break;
          case 0x10: w(r, 163, 1); break;
          case 0x11: w(r, 936, 1); break;
          case 0x12: w(r, 939, 1); break;
          case 0x13: w(r, 515, 1); break;
          case 0x14: w(r, 401, 1); break;
          case 0x15: w(r, 1122, 1); break;
          case 0x16: w(r, 1125, 1); break;
          case 0x17: w(r, 381, 1); break;
          case 0x18: w(r, 1131, 1); break;
          case 0x19: w(r, 1134, 1); break;
          case 0x1a: w(r, 1137, 1); break;
          case 0x1b: w(r, 407, 1); break;
          case 0x1c: w(r, 1143, 1); break;
          case 0x1d: w(r, 162, 1); break;
          case 0x1e: w(r, 1149, 1); break;
          case 0x1f: w(r, 869, 1); break;
          case 0x20: w(r, 1155, 1); break;
          case 0x21: w(r, 1158, 1); break;
          case 0x22: w(r, 40, 1); break;
          case 0x23: w(r, 383, 1); break;
          case 0x24: w(r, 331, 1); break;
          case 0x25: w(r, 41, 1); break;
          case 0x26: w(r, 518, 1); break;
          case 0x27: w(r, 593, 1); break;
          case 0x28: w(r, 361, 1); break;
          case 0x29: w(r, 380, 1); break;
          case 0x2a: w(r, 167, 1); break;
          case 0x2b: w(r, 1047, 1); break;
          case 0x2c: w(r, 330, 1); break;
          case 0x2d: w(r, 333, 1); break;
          case 0x2e: w(r, 334, 1); break;
          case 0x2f: w(r, 1059, 1); break;
          case 0x30: w(r, 480, 1); break;
          case 0x31: w(r, 366, 1); break;
          case 0x32: w(r, 1071, 1); break;
          case 0x33: w(r, 39, 1); break;
          case 0x34: w(r, 43, 1); break;
          case 0x35: w(r, 1089, 1); break;
          case 0x36: w(r, 967, 1); break;
          case 0x37: w(r, 166, 1); break;
          case 0x38: w(r, 1098, 1); break;
          case 0x39: w(r, 872, 1); break;
          case 0x3a: w(r, 1104, 1); break;
          case 0x3b: w(r, 400, 1); break;
          case 0x3c: w(r, 491, 1); break;
          case 0x3d: w(r, 912, 1); break;
          case 0x3e: w(r, 358, 1); break;
          case 0x3f: w(r, 517, 1); break;
          case 0x40: w(r, 921, 1); break;
          case 0x41: w(r, 924, 1); break;
          case 0x42: w(r, 404, 1); break;
          case 0x43: w(r, 399, 1); break;
          case 0x44: w(r, 163, 1); break;
          case 0x45: w(r, 936, 1); break;
          case 0x46: w(r, 939, 1); break;
          case 0x47: w(r, 515, 1); break;
          case 0x48: w(r, 401, 1); break;
          case 0x49: w(r, 1122, 1); break;
          case 0x4a: w(r, 1125, 1); break;
          case 0x4b: w(r, 381, 1); break;
          case 0x4c: w(r, 1131, 1); break;
          case 0x4d: w(r, 1134, 1); break;
          case 0x4e: w(r, 1137, 1); break;
          case 0x4f: w(r, 407, 1); break;
          case 0x50: w(r, 1143, 1); break;
          case 0x51: w(r, 162, 1); break;
          case 0x52: w(r, 1149, 1); break;
          case 0x53: w(r, 869, 1); break;
          case 0x54: w(r, 1155, 1); break;
          case 0x55: w(r, 1158, 1); break;
          case 0x56: w(r, 40, 1); break;
          case 0x57: w(r, 383, 1); break;
          case 0x58: w(r, 331, 1); break;
          case 0x59: w(r, 41, 1); break;
          case 0x5a: w(r, 518, 1); break;
          case 0x5b: w(r, 593, 1); break;
          case 0x5c: w(r, 361, 1); break;
          case 0x5d: w(r, 380, 1); break;
          case 0x5e: w(r, 167, 1); break;
          case 0x5f: w(r, 1047, 1); break;
          case 0x60: w(r, 330, 1); break;
          case 0x61: w(r, 333, 1); break;
          case 0x62: w(r, 334, 1); break;
          case 0x63: w(r, 1059, 1); break;
          case 0x64: w(r, 480, 1); break;
          case 0x65: w(r, 366, 1); break;
          case 0x66: w(r, 1071, 1); break;
          case 0x67: w(r, 39, 1); break;
          case 0x68: w(r, 43, 1); break;
          case 0x69: w(r, 1089, 1); break;
          case 0x6a: w(r, 967, 1); break;
          case 0x6b: w(r, 166, 1); break;
          case 0x6c: w(r, 1098, 1); break;
          case 0x6d: w(r, 872, 1); break;
          case 0x6e: w(r, 1104, 1); break;
          case 0x6f: w(r, 400, 1); break;
          case 0x70: w(r, 491, 1); break;
          case 0x71: w(r, 912, 1); break;
          case 0x72: w(r, 358, 1); break;
          case 0x73: w(r, 517, 1); break;
          case 0x74: w(r, 921, 1); break;
          case 0x75: w(r, 924, 1); break;
          case 0x76: w(r, 404, 1); break;
          case 0x77: w(r, 399, 1); break;
          case 0x78: w(r, 163, 1); break;
          case 0x79: w(r, 936, 1); break;
          case 0x7a: w(r, 939, 1); break;
          case 0x7b: w(r, 515, 1); break;
          case 0x7c: w(r, 401, 1); break;
          case 0x7d: w(r, 1122, 1); break;
          case 0x7e: w(r, 1125, 1); break;
          case 0x7f: w(r, 381, 1); break;
          case 0x80: w(r, 1131, 1); break;
          case 0x81: w(r, 1134, 1); break;
          case 0x82: w(r, 1137, 1); break;
          case 0x83: w(r, 407, 1); break;
          case 0x84: w(r, 1143, 1); break;
          case 0x85: w(r, 162, 1); break;
          case 0x86: w(r, 1149, 1); break;
          case 0x87: w(r, 869, 1); break;
          case 0x88: w(r, 1155, 1); break;
          case 0x89: w(r, 1158, 1); break;
          case 0x8a: w(r, 40, 1); break;
          case 0x8b: w(r, 383, 1); break;
          case 0x8c: w(r, 331, 1); break;
          case 0x8d: w(r, 41, 1); break;
          case 0x8e: w(r, 518, 1); break;
          case 0x8f: w(r, 593, 1); break;
          case 0x90: w(r, 361, 1); break;
          case 0x91: w(r, 380, 1); break;
          case 0x92: w(r, 167, 1); break;
          case 0x93: w(r, 1047, 1); break;
          case 0x94: w(r, 330, 1); break;
          case 0x95: w(r, 333, 1); break;
          case 0x96: w(r, 334, 1); break;
          case 0x97: w(r, 1059, 1); break;
          case 0x98: w(r, 480, 1); break;
          case 0x99: w(r, 366, 1); break;
          case 0x9a: w(r, 1071, 1); break;
          case 0x9b: w(r, 39, 1); break;
          case 0x9c: w(r, 43, 1); break;
          case 0x9d: w(r, 1089, 1); break;
          case 0x9e: w(r, 967, 1); break;
          case 0x9f: w(r, 166, 1); break;
          case 0xa0: w(r, 1098, 1); break;
          case 0xa1: w(r, 872, 1); break;
          case 0xa2: w(r, 1104, 1); break;
          case 0xa3: w(r, 400, 1); break;
          case 0xa4: w(r, 1822, 1); break;
          case 0xa5: w(r, 1821, 1); break;
          case 0xa8: w(r, 1820, 1); break;
          case 0xa9: w(r, 1819, 1); break;
          case 0xaa: w(r, 1818, 1); break;
          case 0xab: w(r, 1817, 1); break;
          case 0xac: w(r, 1816, 1); break;
          case 0xad: w(r, 1815, 1); break;
          case 0xae: w(r, 1814, 1); break;
          case 0xaf: w(r, 1813, 1); break;
          case 0xb0: w(r, 1812, 1); break;
          case 0xb1: w(r, 1811, 1); break;
          case 0xb2: w(r, 1810, 1); break;
          case 0xb3: w(r, 1809, 1); break;
          case 0xb4: w(r, 1808, 1); break;
          case 0xb5: w(r, 1807, 1); break;
          case 0xb6: w(r, 1842, 1); break;
          case 0xb7: w(r, 1841, 1); break;
          case 0xb8: w(r, 1840, 1); break;
          case 0xb9: w(r, 1813, 1); break;
          case 0xba: w(r, 1839, 1); break;
          case 0xbb: w(r, 1838, 1); break;
          case 0xbc: w(r, 1837, 1); break;
          case 0xbd: w(r, 1836, 1); break;
          case 0xbe: w(r, 1835, 1); break;
          case 0xbf: w(r, 1834, 1); break;
          case 0xc0: w(r, 1333, 1); break;
          case 0xc1: w(r, 1833, 1); break;
          case 0xc2: w(r, 1832, 1); break;
          case 0xc3: w(r, 1831, 1); break;
          case 0xc4: w(r, 1845, 1); break;
          case 0xc5: w(r, 1844, 1); break;
          case 0xc6: w(r, 1828, 1); break;
          case 0xc7: w(r, 1843, 1); break;
          case 0xc8: w(r, 1857, 1); break;
          case 0xc9: w(r, 1827, 1); break;
          case 0xca: w(r, 1856, 1); break;
          case 0xcb: w(r, 1826, 1); break;
          case 0xcc: w(r, 1855, 1); break;
          case 0xcd: w(r, 1244, 1); break;
          case 0xce: w(r, 1854, 1); break;
          case 0xcf: w(r, 1853, 1); break;
          case 0xd0: w(r, 1852, 1); break;
          case 0xd1: w(r, 1823, 1); break;
          case 0xd2: w(r, 1824, 1); break;
          case 0xd3: w(r, 1851, 1); break;
          case 0xd4: w(r, 1850, 1); break;
          case 0xd5: w(r, 1849, 1); break;
          case 0xd6: w(r, 1848, 1); break;
          case 0xd7: w(r, 1825, 1); break;
          case 0xd8: w(r, 1847, 1); break;
          case 0xd9: w(r, 1846, 1); break;
          case 0xda: w(r, 1830, 1); break;
          case 0xdb: w(r, 1829, 1); break;
          case 0xdc: w(r, 1828, 1); break;
          case 0xdd: w(r, 1827, 1); break;
          case 0xde: w(r, 1826, 1); break;
          case 0xdf: w(r, 1825, 1); break;
          case 0xe0: w(r, 1824, 1); break;
          case 0xe1: w(r, 1823, 1); break;
          case 0xe2: w(r, 1820, 1); break;
          case 0xe3: w(r, 1819, 1); break;
          case 0xe4: w(r, 1818, 1); break;
          case 0xe5: w(r, 1817, 1); break;
          case 0xe6: w(r, 1816, 1); break;
          case 0xe7: w(r, 1815, 1); break;
          case 0xe8: w(r, 1814, 1); break;
          case 0xe9: w(r, 1813, 1); break;
          case 0xea: w(r, 1812, 1); break;
          case 0xeb: w(r, 1811, 1); break;
          case 0xec: w(r, 1810, 1); break;
          case 0xed: w(r, 1809, 1); break;
          case 0xee: w(r, 1808, 1); break;
          case 0xef: w(r, 1807, 1); break;
          case 0xf0: w(r, 1842, 1); break;
          case 0xf1: w(r, 1841, 1); break;
          case 0xf2: w(r, 1840, 1); break;
          case 0xf3: w(r, 1813, 1); break;
          case 0xf4: w(r, 1839, 1); break;
          case 0xf5: w(r, 1838, 1); break;
          case 0xf6: w(r, 1837, 1); break;
          case 0xf7: w(r, 1836, 1); break;
          case 0xf8: w(r, 1835, 1); break;
          case 0xf9: w(r, 1834, 1); break;
          case 0xfa: w(r, 1333, 1); break;
          case 0xfb: w(r, 1833, 1); break;
          case 0xfc: w(r, 1832, 1); break;
          case 0xfd: w(r, 1831, 1); break;
          case 0xfe: w(r, 1845, 1); break;
          case 0xff: w(r, 1844, 1); break;
          default: r.push_back(c);
          }
        }
        break;
        case 0xd700:
        {
          switch (static_cast<uint8_t>(c & 0xff))
          {
          case 0x0: w(r, 1828, 1); break;
          case 0x1: w(r, 1843, 1); break;
          case 0x2: w(r, 1857, 1); break;
          case 0x3: w(r, 1827, 1); break;
          case 0x4: w(r, 1856, 1); break;
          case 0x5: w(r, 1826, 1); break;
          case 0x6: w(r, 1855, 1); break;
          case 0x7: w(r, 1244, 1); break;
          case 0x8: w(r, 1854, 1); break;
          case 0x9: w(r, 1853, 1); break;
          case 0xa: w(r, 1852, 1); break;
          case 0xb: w(r, 1823, 1); break;
          case 0xc: w(r, 1824, 1); break;
          case 0xd: w(r, 1851, 1); break;
          case 0xe: w(r, 1850, 1); break;
          case 0xf: w(r, 1849, 1); break;
          case 0x10: w(r, 1848, 1); break;
          case 0x11: w(r, 1825, 1); break;
          case 0x12: w(r, 1847, 1); break;
          case 0x13: w(r, 1846, 1); break;
          case 0x14: w(r, 1830, 1); break;
          case 0x15: w(r, 1829, 1); break;
          case 0x16: w(r, 1828, 1); break;
          case 0x17: w(r, 1827, 1); break;
          case 0x18: w(r, 1826, 1); break;
          case 0x19: w(r, 1825, 1); break;
          case 0x1a: w(r, 1824, 1); break;
          case 0x1b: w(r, 1823, 1); break;
          case 0x1c: w(r, 1820, 1); break;
          case 0x1d: w(r, 1819, 1); break;
          case 0x1e: w(r, 1818, 1); break;
          case 0x1f: w(r, 1817, 1); break;
          case 0x20: w(r, 1816, 1); break;
          case 0x21: w(r, 1815, 1); break;
          case 0x22: w(r, 1814, 1); break;
          case 0x23: w(r, 1813, 1); break;
          case 0x24: w(r, 1812, 1); break;
          case 0x25: w(r, 1811, 1); break;
          case 0x26: w(r, 1810, 1); break;
          case 0x27: w(r, 1809, 1); break;
          case 0x28: w(r, 1808, 1); break;
          case 0x29: w(r, 1807, 1); break;
          case 0x2a: w(r, 1842, 1); break;
          case 0x2b: w(r, 1841, 1); break;
          case 0x2c: w(r, 1840, 1); break;
          case 0x2d: w(r, 1813, 1); break;
          case 0x2e: w(r, 1839, 1); break;
          case 0x2f: w(r, 1838, 1); break;
          case 0x30: w(r, 1837, 1); break;
          case 0x31: w(r, 1836, 1); break;
          case 0x32: w(r, 1835, 1); break;
          case 0x33: w(r, 1834, 1); break;
          case 0x34: w(r, 1333, 1); break;
          case 0x35: w(r, 1833, 1); break;
          case 0x36: w(r, 1832, 1); break;
          case 0x37: w(r, 1831, 1); break;
          case 0x38: w(r, 1845, 1); break;
          case 0x39: w(r, 1844, 1); break;
          case 0x3a: w(r, 1828, 1); break;
          case 0x3b: w(r, 1843, 1); break;
          case 0x3c: w(r, 1857, 1); break;
          case 0x3d: w(r, 1827, 1); break;
          case 0x3e: w(r, 1856, 1); break;
          case 0x3f: w(r, 1826, 1); break;
          case 0x40: w(r, 1855, 1); break;
          case 0x41: w(r, 1244, 1); break;
          case 0x42: w(r, 1854, 1); break;
          case 0x43: w(r, 1853, 1); break;
          case 0x44: w(r, 1852, 1); break;
          case 0x45: w(r, 1823, 1); break;
          case 0x46: w(r, 1824, 1); break;
          case 0x47: w(r, 1851, 1); break;
          case 0x48: w(r, 1850, 1); break;
          case 0x49: w(r, 1849, 1); break;
          case 0x4a: w(r, 1848, 1); break;
          case 0x4b: w(r, 1825, 1); break;
          case 0x4c: w(r, 1847, 1); break;
          case 0x4d: w(r, 1846, 1); break;
          case 0x4e: w(r, 1830, 1); break;
          case 0x4f: w(r, 1829, 1); break;
          case 0x50: w(r, 1828, 1); break;
          case 0x51: w(r, 1827, 1); break;
          case 0x52: w(r, 1826, 1); break;
          case 0x53: w(r, 1825, 1); break;
          case 0x54: w(r, 1824, 1); break;
          case 0x55: w(r, 1823, 1); break;
          case 0x56: w(r, 1820, 1); break;
          case 0x57: w(r, 1819, 1); break;
          case 0x58: w(r, 1818, 1); break;
          case 0x59: w(r, 1817, 1); break;
          case 0x5a: w(r, 1816, 1); break;
          case 0x5b: w(r, 1815, 1); break;
          case 0x5c: w(r, 1814, 1); break;
          case 0x5d: w(r, 1813, 1); break;
          case 0x5e: w(r, 1812, 1); break;
          case 0x5f: w(r, 1811, 1); break;
          case 0x60: w(r, 1810, 1); break;
          case 0x61: w(r, 1809, 1); break;
          case 0x62: w(r, 1808, 1); break;
          case 0x63: w(r, 1807, 1); break;
          case 0x64: w(r, 1842, 1); break;
          case 0x65: w(r, 1841, 1); break;
          case 0x66: w(r, 1840, 1); break;
          case 0x67: w(r, 1813, 1); break;
          case 0x68: w(r, 1839, 1); break;
          case 0x69: w(r, 1838, 1); break;
          case 0x6a: w(r, 1837, 1); break;
          case 0x6b: w(r, 1836, 1); break;
          case 0x6c: w(r, 1835, 1); break;
          case 0x6d: w(r, 1834, 1); break;
          case 0x6e: w(r, 1333, 1); break;
          case 0x6f: w(r, 1833, 1); break;
          case 0x70: w(r, 1832, 1); break;
          case 0x71: w(r, 1831, 1); break;
          case 0x72: w(r, 1845, 1); break;
          case 0x73: w(r, 1844, 1); break;
          case 0x74: w(r, 1828, 1); break;
          case 0x75: w(r, 1843, 1); break;
          case 0x76: w(r, 1857, 1); break;
          case 0x77: w(r, 1827, 1); break;
          case 0x78: w(r, 1856, 1); break;
          case 0x79: w(r, 1826, 1); break;
          case 0x7a: w(r, 1855, 1); break;
          case 0x7b: w(r, 1244, 1); break;
          case 0x7c: w(r, 1854, 1); break;
          case 0x7d: w(r, 1853, 1); break;
          case 0x7e: w(r, 1852, 1); break;
          case 0x7f: w(r, 1823, 1); break;
          case 0x80: w(r, 1824, 1); break;
          case 0x81: w(r, 1851, 1); break;
          case 0x82: w(r, 1850, 1); break;
          case 0x83: w(r, 1849, 1); break;
          case 0x84: w(r, 1848, 1); break;
          case 0x85: w(r, 1825, 1); break;
          case 0x86: w(r, 1847, 1); break;
          case 0x87: w(r, 1846, 1); break;
          case 0x88: w(r, 1830, 1); break;
          case 0x89: w(r, 1829, 1); break;
          case 0x8a: w(r, 1828, 1); break;
          case 0x8b: w(r, 1827, 1); break;
          case 0x8c: w(r, 1826, 1); break;
          case 0x8d: w(r, 1825, 1); break;
          case 0x8e: w(r, 1824, 1); break;
          case 0x8f: w(r, 1823, 1); break;
          case 0x90: w(r, 1820, 1); break;
          case 0x91: w(r, 1819, 1); break;
          case 0x92: w(r, 1818, 1); break;
          case 0x93: w(r, 1817, 1); break;
          case 0x94: w(r, 1816, 1); break;
          case 0x95: w(r, 1815, 1); break;
          case 0x96: w(r, 1814, 1); break;
          case 0x97: w(r, 1813, 1); break;
          case 0x98: w(r, 1812, 1); break;
          case 0x99: w(r, 1811, 1); break;
          case 0x9a: w(r, 1810, 1); break;
          case 0x9b: w(r, 1809, 1); break;
          case 0x9c: w(r, 1808, 1); break;
          case 0x9d: w(r, 1807, 1); break;
          case 0x9e: w(r, 1842, 1); break;
          case 0x9f: w(r, 1841, 1); break;
          case 0xa0: w(r, 1840, 1); break;
          case 0xa1: w(r, 1813, 1); break;
          case 0xa2: w(r, 1839, 1); break;
          case 0xa3: w(r, 1838, 1); break;
          case 0xa4: w(r, 1837, 1); break;
          case 0xa5: w(r, 1836, 1); break;
          case 0xa6: w(r, 1835, 1); break;
          case 0xa7: w(r, 1834, 1); break;
          case 0xa8: w(r, 1333, 1); break;
          case 0xa9: w(r, 1833, 1); break;
          case 0xaa: w(r, 1832, 1); break;
          case 0xab: w(r, 1831, 1); break;
          case 0xac: w(r, 1845, 1); break;
          case 0xad: w(r, 1844, 1); break;
          case 0xae: w(r, 1828, 1); break;
          case 0xaf: w(r, 1843, 1); break;
          case 0xb0: w(r, 1857, 1); break;
          case 0xb1: w(r, 1827, 1); break;
          case 0xb2: w(r, 1856, 1); break;
          case 0xb3: w(r, 1826, 1); break;
          case 0xb4: w(r, 1855, 1); break;
          case 0xb5: w(r, 1244, 1); break;
          case 0xb6: w(r, 1854, 1); break;
          case 0xb7: w(r, 1853, 1); break;
          case 0xb8: w(r, 1852, 1); break;
          case 0xb9: w(r, 1823, 1); break;
          case 0xba: w(r, 1824, 1); break;
          case 0xbb: w(r, 1851, 1); break;
          case 0xbc: w(r, 1850, 1); break;
          case 0xbd: w(r, 1849, 1); break;
          case 0xbe: w(r, 1848, 1); break;
          case 0xbf: w(r, 1825, 1); break;
          case 0xc0: w(r, 1847, 1); break;
          case 0xc1: w(r, 1846, 1); break;
          case 0xc2: w(r, 1830, 1); break;
          case 0xc3: w(r, 1829, 1); break;
          case 0xc4: w(r, 1828, 1); break;
          case 0xc5: w(r, 1827, 1); break;
          case 0xc6: w(r, 1826, 1); break;
          case 0xc7: w(r, 1825, 1); break;
          case 0xc8: w(r, 1824, 1); break;
          case 0xc9: w(r, 1823, 1); break;
          case 0xca: w(r, 1859, 1); break;
          case 0xcb: w(r, 1858, 1); break;
          case 0xce: w(r, 161, 1); break;
          case 0xcf: w(r, 158, 1); break;
          case 0xd0: w(r, 44, 1); break;
          case 0xd1: w(r, 184, 1); break;
          case 0xd2: w(r, 188, 1); break;
          case 0xd3: w(r, 192, 1); break;
          case 0xd4: w(r, 196, 1); break;
          case 0xd5: w(r, 200, 1); break;
          case 0xd6: w(r, 204, 1); break;
          case 0xd7: w(r, 208, 1); break;
          case 0xd8: w(r, 161, 1); break;
          case 0xd9: w(r, 158, 1); break;
          case 0xda: w(r, 44, 1); break;
          case 0xdb: w(r, 184, 1); break;
          case 0xdc: w(r, 188, 1); break;
          case 0xdd: w(r, 192, 1); break;
          case 0xde: w(r, 196, 1); break;
          case 0xdf: w(r, 200, 1); break;
          case 0xe0: w(r, 204, 1); break;
          case 0xe1: w(r, 208, 1); break;
          case 0xe2: w(r, 161, 1); break;
          case 0xe3: w(r, 158, 1); break;
          case 0xe4: w(r, 44, 1); break;
          case 0xe5: w(r, 184, 1); break;
          case 0xe6: w(r, 188, 1); break;
          case 0xe7: w(r, 192, 1); break;
          case 0xe8: w(r, 196, 1); break;
          case 0xe9: w(r, 200, 1); break;
          case 0xea: w(r, 204, 1); break;
          case 0xeb: w(r, 208, 1); break;
          case 0xec: w(r, 161, 1); break;
          case 0xed: w(r, 158, 1); break;
          case 0xee: w(r, 44, 1); break;
          case 0xef: w(r, 184, 1); break;
          case 0xf0: w(r, 188, 1); break;
          case 0xf1: w(r, 192, 1); break;
          case 0xf2: w(r, 196, 1); break;
          case 0xf3: w(r, 200, 1); break;
          case 0xf4: w(r, 204, 1); break;
          case 0xf5: w(r, 208, 1); break;
          case 0xf6: w(r, 161, 1); break;
          case 0xf7: w(r, 158, 1); break;
          case 0xf8: w(r, 44, 1); break;
          case 0xf9: w(r, 184, 1); break;
          case 0xfa: w(r, 188, 1); break;
          case 0xfb: w(r, 192, 1); break;
          case 0xfc: w(r, 196, 1); break;
          case 0xfd: w(r, 200, 1); break;
          case 0xfe: w(r, 204, 1); break;
          case 0xff: w(r, 208, 1); break;
          default: r.push_back(c);
          }
        }
        break;
        case 0xf100:
        {
          switch (static_cast<uint8_t>(c & 0xff))
          {
          case 0x0: w(r, 1164, 2); break;
          case 0x1: w(r, 1612, 2); break;
          case 0x2: w(r, 1614, 2); break;
          case 0x3: w(r, 1616, 2); break;
          case 0x4: w(r, 1618, 2); break;
          case 0x5: w(r, 1620, 2); break;
          case 0x6: w(r, 1622, 2); break;
          case 0x7: w(r, 1624, 2); break;
          case 0x8: w(r, 1626, 2); break;
          case 0x9: w(r, 1628, 2); break;
          case 0xa: w(r, 1602, 2); break;
          case 0x10: w(r, 908, 3); break;
          case 0x11: w(r, 911, 3); break;
          case 0x12: w(r, 914, 3); break;
          case 0x13: w(r, 917, 3); break;
          case 0x14: w(r, 920, 3); break;
          case 0x15: w(r, 923, 3); break;
          case 0x16: w(r, 926, 3); break;
          case 0x17: w(r, 929, 3); break;
          case 0x18: w(r, 932, 3); break;
          case 0x19: w(r, 935, 3); break;
          case 0x1a: w(r, 938, 3); break;
          case 0x1b: w(r, 1115, 3); break;
          case 0x1c: w(r, 1118, 3); break;
          case 0x1d: w(r, 1121, 3); break;
          case 0x1e: w(r, 1124, 3); break;
          case 0x1f: w(r, 1127, 3); break;
          case 0x20: w(r, 1130, 3); break;
          case 0x21: w(r, 1133, 3); break;
          case 0x22: w(r, 1136, 3); break;
          case 0x23: w(r, 1139, 3); break;
          case 0x24: w(r, 1142, 3); break;
          case 0x25: w(r, 1145, 3); break;
          case 0x26: w(r, 1148, 3); break;
          case 0x27: w(r, 1151, 3); break;
          case 0x28: w(r, 1154, 3); break;
          case 0x29: w(r, 1157, 3); break;
          case 0x2a: w(r, 1160, 3); break;
          case 0x2b: w(r, 358, 1); break;
          case 0x2c: w(r, 1134, 1); break;
          case 0x2d: w(r, 1600, 2); break;
          case 0x2e: w(r, 1598, 2); break;
          case 0x30: w(r, 491, 1); break;
          case 0x31: w(r, 912, 1); break;
          case 0x32: w(r, 358, 1); break;
          case 0x33: w(r, 517, 1); break;
          case 0x34: w(r, 921, 1); break;
          case 0x35: w(r, 924, 1); break;
          case 0x36: w(r, 404, 1); break;
          case 0x37: w(r, 399, 1); break;
          case 0x38: w(r, 163, 1); break;
          case 0x39: w(r, 936, 1); break;
          case 0x3a: w(r, 939, 1); break;
          case 0x3b: w(r, 515, 1); break;
          case 0x3c: w(r, 401, 1); break;
          case 0x3d: w(r, 1122, 1); break;
          case 0x3e: w(r, 1125, 1); break;
          case 0x3f: w(r, 381, 1); break;
          case 0x40: w(r, 1131, 1); break;
          case 0x41: w(r, 1134, 1); break;
          case 0x42: w(r, 1137, 1); break;
          case 0x43: w(r, 407, 1); break;
          case 0x44: w(r, 1143, 1); break;
          case 0x45: w(r, 162, 1); break;
          case 0x46: w(r, 1149, 1); break;
          case 0x47: w(r, 869, 1); break;
          case 0x48: w(r, 1155, 1); break;
          case 0x49: w(r, 1158, 1); break;
          case 0x4a: w(r, 1654, 2); break;
          case 0x4b: w(r, 1398, 2); break;
          case 0x4c: w(r, 1630, 2); break;
          case 0x4d: w(r, 1632, 2); break;
          case 0x4e: w(r, 1061, 3); break;
          case 0x4f: w(r, 1634, 2); break;
          case 0x90: w(r, 1636, 2); break;
          default: r.push_back(c);
          }
        }
        break;
        case 0xf200:
        {
          switch (static_cast<uint8_t>(c & 0xff))
          {
          case 0x0: w(r, 1638, 2); break;
          case 0x1: w(r, 1640, 2); break;
          case 0x2: w(r, 71, 1); break;
          case 0x13: w(r, 1456, 1); break;
          case 0x29: w(r, 1209, 1); break;
          case 0x40: w(r, 1642, 2); break;
          case 0x41: w(r, 1642, 2); break;
          case 0x42: w(r, 1642, 2); break;
          case 0x43: w(r, 1642, 2); break;
          case 0x44: w(r, 1642, 2); break;
          case 0x45: w(r, 1642, 2); break;
          case 0x46: w(r, 1642, 2); break;
          case 0x47: w(r, 1642, 2); break;
          case 0x48: w(r, 1642, 2); break;
          default: r.push_back(c);
          }
        }
        break;
        default: r.push_back(c);
        }
      }
        // default: r.push_back(c);
      }
    }
  }

  s.swap(r);
}

}  // namespace strings
