#include <stdio.h>
#include <libakrypt.h>
#include <errno.h>


typedef enum {
	NONE,
	GENERATE,
	VERIFY
} CmacMode;


struct Arguments {
	CmacMode mode;
	char *dataFilename;
	char *imitFilename;
};


int argParse(int argc, char **argv, struct Arguments *arguments) {
	arguments->mode = NONE;
	arguments->dataFilename = NULL;
	arguments->imitFilename = NULL;

	for(int i = 1; i < argc; ++i) {
		if(strcmp(argv[i], "-generate") == 0) {
			arguments->mode = GENERATE;
		} else if(strcmp(argv[i], "-text") == 0) {
			arguments->dataFilename = argv[++i];
		} else if(strcmp(argv[i], "-verify") == 0) {
			arguments->mode = VERIFY;			
		} else if(strcmp(argv[i], "-imit") == 0) {
			arguments->imitFilename = argv[++i];
		}
	}

	if(arguments->mode == NONE || 
	  (arguments->mode == GENERATE && !arguments->dataFilename) || 
	  (arguments->mode == VERIFY && 
	  (!arguments->dataFilename || !arguments->imitFilename))) {
		fprintf(stderr, "Invalid arguments\n");
		exit(EXIT_FAILURE);
	}

	return 0;
}


ak_uint8* readImit(char *filename) {
	FILE *file = fopen(filename, "r");
	ak_uint8 *imitTarget;
	int size;

	fseek(file, 0, SEEK_END);
	size = ftell(file);
	fseek(file, 0, SEEK_SET);

	imitTarget = malloc(size);

	fgets(imitTarget, size, file);
	
	fclose(file);

	return imitTarget;
}


ak_uint8* readData(char *filename, int *length) {
	FILE *file = fopen(filename, "r");
	ak_uint8 *data;
	int size;

	fseek(file, 0, SEEK_END);
	size = ftell(file);
	fseek(file, 0, SEEK_SET);
	
	data = malloc(size);

	fread(data, 1, size, file);

	fclose(file);
	*length = size;

	return data;
}


int main(int argc, char **argv) {
	struct bckey context;
	ak_uint8 *data;
	int dataLength;
	ak_uint8 *imitTarget;
	ak_uint8 imit[16];
	struct Arguments arguments;

	argParse(argc, argv, &arguments);

	if(ak_libakrypt_create(NULL) != ak_true) {
		ak_libakrypt_destroy();
		return EXIT_FAILURE;
	}
	
	data = readData(arguments.dataFilename, &dataLength);

	ak_bckey_create_magma(&context);
	ak_bckey_set_key_from_password(&context, "miem", 4, "hse", 3);

	ak_bckey_cmac(&context, arguments.dataFilename, dataLength, imit, 8);

	if(arguments.mode == VERIFY) {
		imitTarget = readImit(arguments.imitFilename);
	}

	printf("%s\n", ak_ptr_to_hexstr(imit, 8, ak_false));
	if(arguments.mode == VERIFY) {
		printf("%s - expected\n", imitTarget);
		if(strcmp(ak_ptr_to_hexstr(imit, 8, ak_false), imitTarget) == 0) {
			printf("Success\n");
		} else {
			printf("Failure\n");
		}
	}

	ak_bckey_destroy(&context);
	ak_libakrypt_destroy();

	return 0;
}
