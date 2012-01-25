#include <python3.2/Python.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

typedef struct block_header_t block_header_t;
struct block_header_t {
	uint8_t version[4];
	uint8_t previous_hash[32];
	uint8_t merkle_root[32];
	uint8_t timestamp[4];
	uint8_t target[4];
	uint8_t nonce[4];
};

typedef union sha256_state_t sha256_state_t;
union sha256_state_t {
	uint32_t h[8];
	char     byte[32];
};

static inline void reverse_bytes(uint8_t *a, size_t n) {
	uint8_t t[n];
	memcpy(t, a, n);
	for (size_t i = 0; i < n; i++) {
		a[i] = t[n - i];
	}
}

static inline void reverse_header(block_header_t *header) {
	reverse_bytes(header->version,       sizeof(header->version));
	reverse_bytes(header->previous_hash, sizeof(header->previous_hash));
	reverse_bytes(header->merkle_root,   sizeof(header->merkle_root));
	reverse_bytes(header->timestamp,     sizeof(header->timestamp));
	reverse_bytes(header->target,        sizeof(header->target));
	reverse_bytes(header->nonce,         sizeof(header->nonce));
}

static uint32_t h[] = {
	0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
};

static uint32_t k[] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

static inline uint32_t ror32(const uint32_t v, const uint32_t n) {
	return (v >> n) | (v << (32 - n));
};

static inline void update_state(sha256_state_t *state, const uint32_t data[16]) {
	uint32_t w[64];
	sha256_state_t t = *state;

	memcpy(w, data, sizeof(uint32_t) * 16);
	for (size_t i = 16; i < 64; i++) {
		uint32_t s0 = ror32(w[i - 15], 7) ^ ror32(w[i - 15], 18) ^ ror32(w[i - 15],  3);
		uint32_t s1 = ror32(w[i - 2], 17) ^ ror32(w[i -  2], 19) ^ ror32(w[i -  2], 10);
		w[i] = w[i - 16] + s0 + w[i - 7] + s1;
	}

	for (size_t i = 0; i < 64; i++) {
        uint32_t s0  = ror32(t.h[0], 2) ^ ror32(t.h[0], 13) ^ ror32(t.h[0], 22);
		uint32_t maj = (t.h[0] & t.h[1]) ^ (t.h[0] & t.h[2]) ^ (t.h[1] & t.h[2]);
		uint32_t t2  = s0 + maj;
        uint32_t s1  = ror32(t.h[4], 6) ^ ror32(t.h[4], 11) ^ ror32(t.h[4], 25);
		uint32_t ch  = (t.h[4] & t.h[5]) ^ (~t.h[4] & t.h[6]);
		uint32_t t1  = t.h[7] + s1 + ch + k[i] + w[i];

		t.h[7] = t.h[6];
		t.h[6] = t.h[5];
		t.h[5] = t.h[4];
		t.h[4] = t.h[3] + t1;
		t.h[3] = t.h[2];
		t.h[2] = t.h[1];
		t.h[1] = t.h[0];
		t.h[0] = t1 + t2;
	}

	for (size_t i = 0; i < 8; i++) {
		state->h[i] += t.h[i];
	}
}

static inline void init_state(sha256_state_t *state) {
	for (size_t i = 0; i < 8; i++) {
		state->h[i] = h[i];
	}
}

static sha256_state_t midstate(const char data[64]) {
	sha256_state_t state;

	init_state(&state);
	update_state(&state, (const uint32_t const *) data);

	return state;
}

PyObject *midstate_helper(PyObject *self, PyObject *arg) {
	Py_ssize_t s;
	char *t, *data;
	sha256_state_t mstate;

	if (PyBytes_Check(arg) != true) { 
		printf("no byte array\n");
		goto error; 
	}
	if (PyBytes_AsStringAndSize(arg, &t, &s) == -1) { goto error; }
	if (s < 64) { goto error; }
	data = malloc(s);
	memcpy(data, t, s);
	// TODO: endianess
	mstate = midstate(data);
	for (size_t i = 0; i < s; i++) {
		printf("%02hhX", data[i]);
	}
	printf("\n");
	free(data);
	return PyBytes_FromStringAndSize(mstate.byte, sizeof(mstate));

error:
	Py_RETURN_NONE;
}

static struct PyMethodDef midstate_functions[] = {
	{"midstate", midstate_helper, METH_O, NULL},
	{NULL, NULL, 0, NULL},
};


static struct PyModuleDef midstatemodule = {
	PyModuleDef_HEAD_INIT,
	"midstate",
	NULL,
	-1,
	midstate_functions,
	NULL,
	NULL,
	NULL,
	NULL
};

PyMODINIT_FUNC
PyInit_midstate(void)
{
	return PyModule_Create(&midstatemodule);
}
