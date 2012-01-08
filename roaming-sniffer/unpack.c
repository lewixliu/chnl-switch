/**
 * @file unpack.c
 * @brief Functions for unpacking Radiotap fields.
 * @details When parsing Radiotap header we traverse it_present bitmap
 * which can be extended. Using those bitmaps we know what fields
 * to expect. Radiotap fields need to be packed in natural boundaries.
 *
 * @author Marcin Harasimczuk
 */

#include "ieee802_11.h"

/**
 * @brief Align pointer to next wordsize boundary.
 */
static u_int8_t *
unpack_align(u_int8_t *fields, u_int8_t *next, size_t alignment)
{
        /* Calculate any bits above chosen wordsize (alignment) */
	size_t misalignment = (size_t)(next - fields) % alignment;

	if (misalignment == 0)
		return next;

        /* Return updated next pointer for new wordsize */
	return next + (alignment - misalignment);
}

/**
 * @brief Move next pointer to next word size boundary. 
 */
static u_int8_t *
unpack_advance(struct unpacker *un, size_t wordsize)
{
	u_int8_t *next;

	/* Ensure alignment. */
	next = unpack_align(un->u_buf, un->u_next, wordsize);

	/* Too little space for wordsize bytes? */
	if (next - un->u_buf + wordsize > un->u_len)
		return NULL;

	return next;
}

int
unpack_init(struct unpacker *un, u_int8_t *buf, size_t buflen)
{
	memset(un, 0, sizeof(*un));

	un->u_buf = buf;
	un->u_len = buflen;
	un->u_next = un->u_buf;

	return 0;
}

/* Unpack a 64-bit unsigned integer. */
int
unpack_uint64(struct unpacker *un, u_int64_t *u)
{
	u_int8_t *next;

	if ((next = unpack_advance(un, sizeof(*u))) == NULL)
		return -1;

	*u = EXTRACT_LE_64BITS(next);

	/* Move pointer past the u_int64_t. */
	un->u_next = next + sizeof(*u);
	return 0;
}

/* Unpack a 32-bit unsigned integer. */
int
unpack_uint32(struct unpacker *un, u_int32_t *u)
{
	u_int8_t *next;

	if ((next = unpack_advance(un, sizeof(*u))) == NULL)
		return -1;

	*u = EXTRACT_LE_32BITS(next);

	/* Move pointer past the u_int32_t. */
	un->u_next = next + sizeof(*u);
	return 0;
}

/* Unpack a 16-bit unsigned integer. */
int
unpack_uint16(struct unpacker *un, u_int16_t *u)
{
	u_int8_t *next;

	if ((next = unpack_advance(un, sizeof(*u))) == NULL)
		return -1;

	*u = EXTRACT_LE_16BITS(next);

	/* Move pointer past the u_int16_t. */
	un->u_next = next + sizeof(*u);
	return 0;
}

/* Unpack an 8-bit unsigned integer. */
int
unpack_uint8(struct unpacker *un, u_int8_t *u)
{
	/* No space left? */
	if ((size_t)(un->u_next - un->u_buf) >= un->u_len)
		return -1;

	*u = *un->u_next;

	/* Move pointer past the u_int8_t. */
	un->u_next++;
	return 0;
}


