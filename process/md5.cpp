/* MD5
 converted to C++ class by Frank Thilo (thilo@unix-ag.org)
 for bzflag (http://www.bzflag.org)

   based on:

   md5.h and md5.c
   reference implemantion of RFC 1321

   Copyright (C) 1991-2, RSA Data Security, Inc. Created 1991. All
rights reserved.

License to copy and use this software is granted provided that it
is identified as the "RSA Data Security, Inc. MD5 Message-Digest
Algorithm" in all material mentioning or referencing this software
or this function.

License is also granted to make and use derivative works provided
that such works are identified as "derived from the RSA Data
Security, Inc. MD5 Message-Digest Algorithm" in all material
mentioning or referencing the derived work.

RSA Data Security, Inc. makes no representations concerning either
the merchantability of this software or the suitability of this
software for any particular purpose. It is provided "as is"
without express or implied warranty of any kind.

These notices must be retained in any copies of any part of this
documentation and/or software.

*/

/* interface header */
#include "md5.hpp"

/* system implementation headers */
#include <cstdio>

namespace Ipxp {

// Constants for MD5Transform routine.
#define S11 7
#define S12 12
#define S13 17
#define S14 22
#define S21 5
#define S22 9
#define S23 14
#define S24 20
#define S31 4
#define S32 11
#define S33 16
#define S34 23
#define S41 6
#define S42 10
#define S43 15
#define S44 21

///////////////////////////////////////////////

// F, G, H and I are basic MD5 functions.
inline MD5::uint4 MD5::f(uint4 x, uint4 y, uint4 z)
{
	return (x & y) | (~x & z);
}

inline MD5::uint4 MD5::g(uint4 x, uint4 y, uint4 z)
{
	return (x & z) | (y & ~z);
}

inline MD5::uint4 MD5::h(uint4 x, uint4 y, uint4 z)
{
	return x ^ y ^ z;
}

inline MD5::uint4 MD5::i(uint4 x, uint4 y, uint4 z)
{
	return y ^ (x | ~z);
}

// rotate_left rotates x left n bits.
inline MD5::uint4 MD5::rotateLeft(uint4 x, int n)
{
	return (x << n) | (x >> (32 - n));
}

// FF, GG, HH, and II transformations for rounds 1, 2, 3, and 4.
// Rotation is separate from addition to prevent recomputation.
inline void MD5::ff(uint4& a, uint4 b, uint4 c, uint4 d, uint4 x, uint4 s, uint4 ac)
{
	a = rotateLeft(a + f(b, c, d) + x + ac, s) + b;
}

inline void MD5::gg(uint4& a, uint4 b, uint4 c, uint4 d, uint4 x, uint4 s, uint4 ac)
{
	a = rotateLeft(a + g(b, c, d) + x + ac, s) + b;
}

inline void MD5::hh(uint4& a, uint4 b, uint4 c, uint4 d, uint4 x, uint4 s, uint4 ac)
{
	a = rotateLeft(a + h(b, c, d) + x + ac, s) + b;
}

inline void MD5::ii(uint4& a, uint4 b, uint4 c, uint4 d, uint4 x, uint4 s, uint4 ac)
{
	a = rotateLeft(a + i(b, c, d) + x + ac, s) + b;
}

//////////////////////////////////////////////

// default ctor, just initailize
MD5::MD5()
{
	init();
}

//////////////////////////////////////////////

// nifty shortcut ctor, compute MD5 for string and finalize it right away
MD5::MD5(const std::string& text)
{
	init();
	update(text.c_str(), text.length());
	finalize();
}

//////////////////////////////

void MD5::init()
{
	m_finalized = false;

	m_count[0] = 0;
	m_count[1] = 0;

	// load magic initialization constants.
	m_state[0] = 0x67452301;
	m_state[1] = 0xefcdab89;
	m_state[2] = 0x98badcfe;
	m_state[3] = 0x10325476;
}

//////////////////////////////

// decodes input (unsigned char) into output (uint4). Assumes len is a multiple of 4.
void MD5::decode(uint4 output[], const uint1 input[], size_type len)
{
	for (unsigned int i = 0, j = 0; j < len; i++, j += 4)
		output[i] = ((uint4) input[j]) | (((uint4) input[j + 1]) << 8)
			| (((uint4) input[j + 2]) << 16) | (((uint4) input[j + 3]) << 24);
}

//////////////////////////////

// encodes input (uint4) into output (unsigned char). Assumes len is
// a multiple of 4.
void MD5::encode(uint1 output[], const uint4 input[], size_type len)
{
	for (size_type i = 0, j = 0; j < len; i++, j += 4) {
		output[j] = input[i] & 0xff;
		output[j + 1] = (input[i] >> 8) & 0xff;
		output[j + 2] = (input[i] >> 16) & 0xff;
		output[j + 3] = (input[i] >> 24) & 0xff;
	}
}

//////////////////////////////

// apply MD5 algo on a block
void MD5::transform(const uint1 block[BLOCKSIZE])
{
	uint4 a = m_state[0], b = m_state[1], c = m_state[2], d = m_state[3], x[16];
	decode(x, block, BLOCKSIZE);

	/* Round 1 */
	ff(a, b, c, d, x[0], S11, 0xd76aa478); /* 1 */
	ff(d, a, b, c, x[1], S12, 0xe8c7b756); /* 2 */
	ff(c, d, a, b, x[2], S13, 0x242070db); /* 3 */
	ff(b, c, d, a, x[3], S14, 0xc1bdceee); /* 4 */
	ff(a, b, c, d, x[4], S11, 0xf57c0faf); /* 5 */
	ff(d, a, b, c, x[5], S12, 0x4787c62a); /* 6 */
	ff(c, d, a, b, x[6], S13, 0xa8304613); /* 7 */
	ff(b, c, d, a, x[7], S14, 0xfd469501); /* 8 */
	ff(a, b, c, d, x[8], S11, 0x698098d8); /* 9 */
	ff(d, a, b, c, x[9], S12, 0x8b44f7af); /* 10 */
	ff(c, d, a, b, x[10], S13, 0xffff5bb1); /* 11 */
	ff(b, c, d, a, x[11], S14, 0x895cd7be); /* 12 */
	ff(a, b, c, d, x[12], S11, 0x6b901122); /* 13 */
	ff(d, a, b, c, x[13], S12, 0xfd987193); /* 14 */
	ff(c, d, a, b, x[14], S13, 0xa679438e); /* 15 */
	ff(b, c, d, a, x[15], S14, 0x49b40821); /* 16 */

	/* Round 2 */
	gg(a, b, c, d, x[1], S21, 0xf61e2562); /* 17 */
	gg(d, a, b, c, x[6], S22, 0xc040b340); /* 18 */
	gg(c, d, a, b, x[11], S23, 0x265e5a51); /* 19 */
	gg(b, c, d, a, x[0], S24, 0xe9b6c7aa); /* 20 */
	gg(a, b, c, d, x[5], S21, 0xd62f105d); /* 21 */
	gg(d, a, b, c, x[10], S22, 0x2441453); /* 22 */
	gg(c, d, a, b, x[15], S23, 0xd8a1e681); /* 23 */
	gg(b, c, d, a, x[4], S24, 0xe7d3fbc8); /* 24 */
	gg(a, b, c, d, x[9], S21, 0x21e1cde6); /* 25 */
	gg(d, a, b, c, x[14], S22, 0xc33707d6); /* 26 */
	gg(c, d, a, b, x[3], S23, 0xf4d50d87); /* 27 */
	gg(b, c, d, a, x[8], S24, 0x455a14ed); /* 28 */
	gg(a, b, c, d, x[13], S21, 0xa9e3e905); /* 29 */
	gg(d, a, b, c, x[2], S22, 0xfcefa3f8); /* 30 */
	gg(c, d, a, b, x[7], S23, 0x676f02d9); /* 31 */
	gg(b, c, d, a, x[12], S24, 0x8d2a4c8a); /* 32 */

	/* Round 3 */
	hh(a, b, c, d, x[5], S31, 0xfffa3942); /* 33 */
	hh(d, a, b, c, x[8], S32, 0x8771f681); /* 34 */
	hh(c, d, a, b, x[11], S33, 0x6d9d6122); /* 35 */
	hh(b, c, d, a, x[14], S34, 0xfde5380c); /* 36 */
	hh(a, b, c, d, x[1], S31, 0xa4beea44); /* 37 */
	hh(d, a, b, c, x[4], S32, 0x4bdecfa9); /* 38 */
	hh(c, d, a, b, x[7], S33, 0xf6bb4b60); /* 39 */
	hh(b, c, d, a, x[10], S34, 0xbebfbc70); /* 40 */
	hh(a, b, c, d, x[13], S31, 0x289b7ec6); /* 41 */
	hh(d, a, b, c, x[0], S32, 0xeaa127fa); /* 42 */
	hh(c, d, a, b, x[3], S33, 0xd4ef3085); /* 43 */
	hh(b, c, d, a, x[6], S34, 0x4881d05); /* 44 */
	hh(a, b, c, d, x[9], S31, 0xd9d4d039); /* 45 */
	hh(d, a, b, c, x[12], S32, 0xe6db99e5); /* 46 */
	hh(c, d, a, b, x[15], S33, 0x1fa27cf8); /* 47 */
	hh(b, c, d, a, x[2], S34, 0xc4ac5665); /* 48 */

	/* Round 4 */
	ii(a, b, c, d, x[0], S41, 0xf4292244); /* 49 */
	ii(d, a, b, c, x[7], S42, 0x432aff97); /* 50 */
	ii(c, d, a, b, x[14], S43, 0xab9423a7); /* 51 */
	ii(b, c, d, a, x[5], S44, 0xfc93a039); /* 52 */
	ii(a, b, c, d, x[12], S41, 0x655b59c3); /* 53 */
	ii(d, a, b, c, x[3], S42, 0x8f0ccc92); /* 54 */
	ii(c, d, a, b, x[10], S43, 0xffeff47d); /* 55 */
	ii(b, c, d, a, x[1], S44, 0x85845dd1); /* 56 */
	ii(a, b, c, d, x[8], S41, 0x6fa87e4f); /* 57 */
	ii(d, a, b, c, x[15], S42, 0xfe2ce6e0); /* 58 */
	ii(c, d, a, b, x[6], S43, 0xa3014314); /* 59 */
	ii(b, c, d, a, x[13], S44, 0x4e0811a1); /* 60 */
	ii(a, b, c, d, x[4], S41, 0xf7537e82); /* 61 */
	ii(d, a, b, c, x[11], S42, 0xbd3af235); /* 62 */
	ii(c, d, a, b, x[2], S43, 0x2ad7d2bb); /* 63 */
	ii(b, c, d, a, x[9], S44, 0xeb86d391); /* 64 */

	m_state[0] += a;
	m_state[1] += b;
	m_state[2] += c;
	m_state[3] += d;

	// Zeroize sensitive information.
	memset(x, 0, sizeof x);
}

//////////////////////////////

// MD5 block update operation. Continues an MD5 message-digest
// operation, processing another message block
void MD5::update(const unsigned char input[], size_type length)
{
	// compute number of bytes mod 64
	size_type index = m_count[0] / 8 % BLOCKSIZE;

	// Update number of bits
	if ((m_count[0] += (length << 3)) < (length << 3))
		m_count[1]++;
	m_count[1] += (length >> 29);

	// number of bytes we need to fill in buffer
	size_type firstpart = 64 - index;

	size_type i;

	// transform as many times as possible.
	if (length >= firstpart) {
		// fill buffer first, transform
		memcpy(&m_buffer[index], input, firstpart);
		transform(m_buffer);

		// transform chunks of blocksize (64 bytes)
		for (i = firstpart; i + BLOCKSIZE <= length; i += BLOCKSIZE)
			transform(&input[i]);

		index = 0;
	} else
		i = 0;

	// buffer remaining input
	memcpy(&m_buffer[index], &input[i], length - i);
}

//////////////////////////////

// for convenience provide a verson with signed char
void MD5::update(const char input[], size_type length)
{
	update((const unsigned char*) input, length);
}

//////////////////////////////

// MD5 finalization. Ends an MD5 message-digest operation, writing the
// the message digest and zeroizing the context.
MD5& MD5::finalize()
{
	static unsigned char padding[64]
		= {0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		   0,    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		   0,    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

	if (!m_finalized) {
		// Save number of bits
		unsigned char bits[8];
		encode(bits, m_count, 8);

		// pad out to 56 mod 64.
		size_type index = m_count[0] / 8 % 64;
		size_type padLen = (index < 56) ? (56 - index) : (120 - index);
		update(padding, padLen);

		// Append length (before padding)
		update(bits, 8);

		// Store state in digest
		encode(m_digest, m_state, 16);

		// Zeroize sensitive information.
		memset(m_buffer, 0, sizeof m_buffer);
		memset(m_count, 0, sizeof m_count);

		m_finalized = true;
	}

	return *this;
}

//////////////////////////////

// return hex representation of digest as string
std::string MD5::hexdigest() const
{
	if (!m_finalized)
		return "";

	char buf[33];
	for (int i = 0; i < 16; i++)
		sprintf(buf + i * 2, "%02x", m_digest[i]);
	buf[32] = 0;

	return std::string(buf);
}

//////////////////////////////

const unsigned char* MD5::binaryDigest() const
{
	return m_digest;
}

//////////////////////////////

std::ostream& operator<<(std::ostream& out, MD5 md5)
{
	return out << md5.hexdigest();
}

//////////////////////////////

std::string md5(const std::string str)
{
	MD5 md5 = MD5(str);

	return md5.hexdigest();
}

//////////////////////////////

void md5GetBin(const std::string str, void* dest)
{
	MD5 md5 = MD5(str);
	memcpy(dest, md5.binaryDigest(), 16);
}

} // namespace ipxp
