#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include <openssl/sha.h>
#include <openssl/ripemd.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/bn.h>
#include "argon2.h"

#include <assert.h>

#ifdef __unix__
#	include <unistd.h>
#	define SET_BINARY_MODE( handle) ((void)0)
#else
#	include <io.h>
#	define STDIN_FILENO 0
#	define SET_BINARY_MODE( handle) do { if( !isatty( handle)) setmode( handle, O_BINARY); } while(0)
#	pragma warning( disable: 4996)
#endif

#define SIZE(x)    ((sizeof (x)) / (sizeof *(x)))
#define PL(x) (x), ((sizeof (x)) / (sizeof *(x)))
#define LP(x)      ((sizeof (x)) / (sizeof *(x))), (x)
// исполнить e и проверить assert'ом результат
#define ISNT_0(e) do { int is_0 = (e); assert( #e && is_0); } while(0)
// указатель p должен попадать в массив array 
#define P_IN_ARRAY( p, array) do { assert( p >= array); assert( p < &array[ SIZE(array)]); } while(0)

#define POINT_BIN_COMPRESSED_SIZE	33
#define POINT_BIN_UNCOMPRESSED_SIZE	65

// Version of the witness program (between 0 and 16 inclusive)
#define WITVER 0x00

// ==============================================================
uint32_t bech32_polymod_step( int32_t b)
{
	return( (b & 0x1FFFFFF) << 5)
	^ ( -( (b >> 25) & 1) & 0x3b6a57b2UL)
	^ ( -( (b >> 26) & 1) & 0x26508e6dUL)
	^ ( -( (b >> 27) & 1) & 0x1ea119faUL)
	^ ( -( (b >> 28) & 1) & 0x3d4233ddUL)
	^ ( -( (b >> 29) & 1) & 0x2a1462b3UL);
}

// human readable part (chain/network specific)
#define HRP "bc"

// =============================================================
/** print segwit with checksum
 *  \param  witprog	Data bytes for the witness program (between 2 and 40 bytes)
 *  \param  witprog_len	Number of data bytes in witprog
 *  \return -
 */
void print_segwit_with_checksum( const uint8_t *witprog, size_t witprog_len)
{
	enum { max_witprog_len = 40 };
	assert( 2 <= witprog_len && witprog_len <= max_witprog_len);

	static const char bech32map[] = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

	// convert_bits
	uint32_t val = 0;
	int bits = 0;
	uint8_t data[ ((max_witprog_len) * 16 + 16 / 2 + 1) / 10 + 1];  // data[ round( max_witprog_len * log2( 256)/log2( 32)) + 1]
	uint8_t *pdata = data;
	*pdata++ = WITVER;

	while( witprog_len--)
	{
		val = (val << 8) | *witprog++;
		bits += 8;
		while( bits >= 5)
		{
			bits -= 5;
			P_IN_ARRAY( pdata, data);
			*pdata++ = (val >> bits) & 0x1f;
		}
	}
	if (bits)
	{
		P_IN_ARRAY( pdata, data);
		*pdata++ = (val << (5 - bits)) & 0x1f;
	}

	// bech32_encode
	size_t i = 0;
	/*
	static const char hrp[] = HRP;	// human readable part (chain/network specific).
	uint32_t chk = 1;
	while( hrp[i])
		chk = bech32_polymod_step( chk) ^ (hrp[i++] >> 5);
	chk = bech32_polymod_step( chk);
	i = 0;
	while( hrp[i])
		chk = bech32_polymod_step( chk) ^ (hrp[i++] & 0x1f);
	printf( "\n\n"
	"uint32_t chk = 0x%lxUL;\n", chk);
	*/
	uint32_t chk = 0x2318043UL;

	printf( HRP "1");

	size_t data_len = pdata - data;
	for( i = 0; i < data_len; ++i)
	{
		uint8_t c = data[ i];
		chk = bech32_polymod_step( chk) ^ c;
		putchar( bech32map[ c]);
	}
	for( i = 0; i < 6; ++i)
		chk = bech32_polymod_step( chk);

#if WITVER
	chk ^= 0x2bc830a3UL;	// ENCODING_BECH32M
#else
	chk ^= 1;		// ENCODING_BECH32
#endif

	for( i = 0; i < 6; ++i)
		putchar( bech32map[ (chk >> ((5 - i) * 5)) & 0x1f]);
	putchar( '\n');
}

// ==============================================================
void print_base58_with_checksum( uint8_t *src, size_t len)
{
	enum { max_len = 34 };
	assert( 0 < len && len <= max_len);

	static const char base58map[] =	"123456789"
					"ABCDEFGH""JKLMN""PQRSTUVWXYZ"
					"abcdefghijk""mnopqrstuvwxyz";

	uint8_t sha256digest[ SHA256_DIGEST_LENGTH];
	SHA256( src, len, sha256digest);
	SHA256( PL( sha256digest), src + len);
	len += 4;

	char ret[ ((max_len + 4) * 13656582 + 13656582 / 2 + 1) / 10000000 + 2];  // ret[ round( ( max_len + 4) * log2( 256) / log2( 58)) + 2]
	char *pret = ret + SIZE( ret);
	uint8_t *end = src + len;

	*--pret = '\0';
	*--pret = '\n';
	while( src < end)
	{
		if( !*src )
		{
			src++;
			continue;
		}

		uint8_t rest = 0;
		uint8_t *ptr = src;
		while( ptr < end)
		{
			unsigned int c = rest * 256 + *ptr;
			rest   = c % 58;
			*ptr++ = c / 58;
		}
		*--pret = base58map[rest];
		P_IN_ARRAY( pret, ret);
	}

	printf( pret);
}

// ==============================================================
#define HASH160_LEN RIPEMD160_DIGEST_LENGTH
void hash160( const uint8_t *d, size_t n, uint8_t *md)
{
	assert( n);

	uint8_t sha256digest[ SHA256_DIGEST_LENGTH];
	SHA256( d, n, sha256digest);
	RIPEMD160( PL( sha256digest), md);
}

// ==============================================================
int main( const int argc, const char *argv[])
{
	uint8_t buf[ 4*1024];
	SHA256_CTX sha256;
	SHA256_Init( &sha256);

	SET_BINARY_MODE( STDIN_FILENO);
	int readed;
	while( (readed = read( STDIN_FILENO, PL( buf))) > 0)
		SHA256_Update( &sha256, buf, readed);

	if( readed < 0)
	{
		perror( argv[0]);
		return errno;
	}
	uint8_t sha256digest[SHA256_DIGEST_LENGTH];
	SHA256_Final( sha256digest, &sha256);

	uint8_t priv_key_bin[SHA256_DIGEST_LENGTH];
	static const uint8_t salt[ 16] = { 0 };
	// argon2i_hash_raw(t_cost, m_cost, parallelism, pwd, pwdlen, salt, SALTLEN, hash1, HASHLEN);
	int rc = argon2id_hash_raw( 2, 1<<16, 1, PL( sha256digest), PL( salt), PL( priv_key_bin));
	if( ARGON2_OK != rc)
	{
		fprintf( stderr, "argon2id_hash_raw() error: %s\n", argon2_error_message( rc));
		return 1;
	}


	BIGNUM *priv_key = BN_new();
	BN_bin2bn( PL( priv_key_bin), priv_key);

	//BN_hex2bn( &priv_key, "a966eb6058f8ec9f47074a2faadd3dab42e2c60ed05bc34d39d6c0e1d32b8bdf");
	//BN_hex2bn( &priv_key, "0C28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D");
	//BN_hex2bn( &priv_key, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFBAAEDCE6AF48A03BBFD25E8CD0364141");
	//printf( "private key (hexadecimal format):\t%s\n", BN_bn2hex( priv_key));


	printf( "private key (Wallet Import Format):\t");
	uint8_t *p = buf;
	*p++ = 0x80;  // NETWORK_BYTE
	BN_bn2bin( priv_key, p);
	p += BN_num_bytes( priv_key);
	*p++ = 0x01;  // COMPRESSED_FLAG
	print_base58_with_checksum( buf, p - buf);


	static const char
	max_priv_key_hex[] = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFBAAEDCE6AF48A03BBFD25E8CD0364140";
	BIGNUM *max_priv_key = NULL;
	BN_hex2bn( &max_priv_key, max_priv_key_hex);
	if( BN_is_zero( priv_key) || BN_cmp( priv_key, max_priv_key) > 0 )
	{
		fprintf( stderr, "\n%s: error! private key > 0x%s\n", argv[0], max_priv_key_hex);
		return 1;
	}

	// A BN_CTX is a structure that holds BIGNUM temporary variables used by library functions.
	BN_CTX* ctx = BN_CTX_new();
	EC_KEY *eckey = EC_KEY_new_by_curve_name( NID_secp256k1);
	const EC_GROUP *group = EC_KEY_get0_group( eckey);
	EC_POINT *pub_key = EC_POINT_new( group);
	uint8_t pub_key_bin[ POINT_BIN_COMPRESSED_SIZE];
	ISNT_0( EC_KEY_set_private_key( eckey, priv_key));
	ISNT_0( EC_POINT_mul( group, pub_key, priv_key, NULL, NULL, ctx));
	ISNT_0( EC_KEY_set_public_key( eckey, pub_key));
	ISNT_0( EC_POINT_point2oct( group, pub_key, POINT_CONVERSION_COMPRESSED, PL( pub_key_bin), ctx));


	printf( "p2pkh (legacy)  address:\t1");
	p = buf;
	*p++ = 0x00;	// address type version byte
	hash160( PL( pub_key_bin), p);
	p += HASH160_LEN;
	print_base58_with_checksum( buf, p - buf);


	printf( "p2wpkh-p2sh     address:\t");
	uint8_t redeem_script[ 2+HASH160_LEN];
	p = redeem_script;
	*p++ = WITVER;		// witness version
	*p++ = HASH160_LEN;	// push HASH160_LEN bytes
	hash160( PL( pub_key_bin), p);
	p = buf;
	*p++ = 0x05;	// address type version byte
	hash160( PL( redeem_script), p);
	p += HASH160_LEN;
	print_base58_with_checksum( buf, p - buf);


	printf( "p2wpkh (segwit) address:\t");
	hash160( PL( pub_key_bin), buf);
	print_segwit_with_checksum( buf, HASH160_LEN);

	return 0;
}
