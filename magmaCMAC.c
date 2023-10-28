#include <stdio.h>
#include <libakrypt.h>

int main(int argc, char **argv) {
	struct bckey context;
	ak_uint8 data[10] = {'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j'};
	ak_uint8 imit[16];

	if(ak_libakrypt_create(NULL) != ak_true) {
		ak_libakrypt_destroy();
		return EXIT_FAILURE;
	}


	ak_bckey_create_magma(&context);
	ak_bckey_set_key_from_password(&context, "hello", 5, "mars", 4);

	ak_bckey_cmac(&context, data, sizeof(data), imit, 8);

	printf("imit: %s\n", ak_ptr_to_hexstr(imit, 8, ak_false));

	ak_bckey_destroy(&context);
	ak_libakrypt_destroy();

	return 0;
}
