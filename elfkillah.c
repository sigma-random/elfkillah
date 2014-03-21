/*
  Copyright (C) 2014 Fabrizio Curcio aka spike

  This program is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

/*
  This is a simple POC which performs literally a cut of the sections
  headers inside an ELF-32/64 file.
  The kernel need just program headers to load and run a process.
  Section headers are useful for linking and also debugging purposes.
  The operations performed by this program on the ELF files are simple:
  when an ELF file is built, section headers are appended at the end
  of the file, so, cutting the ELF where the section headers starts and
  discarding those contents, does not affect the program functionalities
  when the program will be loaded into memory and executed as a process.
  Doing so forbids disassemblers and some debuggers to analyze the file.
  This is a simple antidebug technique for static and maybe simple dynamic
  analysis.
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdarg.h>
#include <elf.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
    
#define ELF_32 ELFCLASS32
#define ELF_64 ELFCLASS64

typedef struct {
	int type;
	size_t size;
	size_t mmapped;
	size_t strtbloff;
	size_t strtblsize;
	union {
		Elf32_Ehdr *elf32;
		Elf64_Ehdr *elf64;
	};
} ElfContainer;

static void
err_exit(const char *format, ...)
{
	va_list args;
	va_start(args,format);
	vfprintf(stderr,format,args);
	va_end(args);
	exit(EXIT_FAILURE);
}

static void
usage(const char *pname)
{
	fprintf(stderr,"%s a simple ELF-32/64 section stripper\n",pname);
	fprintf(stderr,"%s <infile> <outfile>\n\n",pname);
	fprintf(stderr,"Written by Fabrizio Curcio aka spike, 2014.\n");
	exit(EXIT_SUCCESS);
}

static long
align_to_page(size_t size)
{
	long pg_size;

	pg_size = sysconf(_SC_PAGESIZE);
	if(pg_size == -1)
		err_exit("sysconf()");

	if(size <= pg_size)
		return pg_size;

	else
		return size + pg_size - (size % pg_size);
}

static void
get_string_table(ElfContainer *elfc)
{
	unsigned char *ptr;
	int i;
	size_t offset, size;

	if(elfc->type == ELF_32){
    
		/* Make ptr point to the start of the section headers */
		ptr = (unsigned char *)elfc->elf32;
		ptr += elfc->elf32->e_shoff;
    
		/* Make ptr point to the start of the string table index section header */
		ptr += (elfc->elf32->e_shstrndx * elfc->elf32->e_shentsize);
    
		/* Take offset and size of the string table into the file */    
		offset = ((Elf32_Shdr *)ptr)->sh_offset;
		size = ((Elf32_Shdr *)ptr)->sh_size;
    
	}else if(elfc->type == ELF_64){

		/* Same thing as above, just now for 64 bits */
		ptr = (unsigned char *)elfc->elf64;
		ptr += elfc->elf64->e_shoff;
		ptr += (elfc->elf64->e_shstrndx * elfc->elf64->e_shentsize);

		offset = ((Elf64_Shdr *)ptr)->sh_offset;
		size = ((Elf64_Shdr *)ptr)->sh_size;

	}else
		err_exit("get_string_table()\n");

	elfc->strtbloff = offset;
	elfc->strtblsize = size;
}

static ElfContainer *
build_container(const char *file)
{
	ElfContainer *elfc;
	unsigned char *id;
	void *ptr;
	int fd;
	size_t size;
	size_t mmapped;
	struct stat sb;

	fd = open(file,O_RDWR);
	if(fd == -1)
		err_exit("build_container() --> open(%s)\n",file);

	if(fstat(fd,&sb) == -1)
		err_exit("build_container() --> fstat()\n");

	size = sb.st_size;
	mmapped = align_to_page(size);
  
	ptr = mmap(NULL,mmapped,PROT_READ|PROT_WRITE,MAP_SHARED,fd,0);

	if(ptr == MAP_FAILED)
		err_exit("build_container() --> mmap()\n");
  
	id = (unsigned char *)ptr;
	if(id[EI_MAG0] != ELFMAG0 || id[EI_MAG1] != ELFMAG1
	   || id[EI_MAG2] != ELFMAG2 || id[EI_MAG3] != ELFMAG3)
		err_exit("build_container() --> bad file\n");

	elfc = (ElfContainer *)malloc(sizeof(ElfContainer));

	if(elfc == NULL)
		err_exit("build_container() --> malloc()\n");

	elfc->size = size;
	elfc->mmapped = mmapped;
  
	if(id[EI_CLASS] == ELF_32){
		elfc->type = ELF_32;
		elfc->elf32 = (Elf32_Ehdr *)ptr;
	}else if(id[EI_CLASS] == ELF_64){
		elfc->type = ELF_64;
		elfc->elf64 = (Elf64_Ehdr *)ptr;
	}else{
		free(elfc);
		err_exit("build_container() --> bad class\n");
	}

	get_string_table(elfc);

	close(fd);

	return elfc;
}

static void
destroy_container(ElfContainer *elfc)
{
	if(elfc == NULL)
		err_exit("destroy_container()\n");
	else if(elfc->type == ELF_32){
		munmap(elfc->elf32,elfc->mmapped);
	}else
		munmap(elfc->elf64,elfc->mmapped);

	free(elfc);
}

static void
adjust_header(ElfContainer *elfc)
{
	unsigned char *ptr;
	int i;

	if(elfc->type == ELF_32){
		elfc->elf32->e_shoff = 0;
		elfc->elf32->e_shentsize = 0;
		elfc->elf32->e_shnum = 0;
		elfc->elf32->e_shstrndx = 0;
		ptr = (unsigned char *)elfc->elf32;
	}else if(elfc->type == ELF_64){
		elfc->elf64->e_shoff = 0;
		elfc->elf64->e_shentsize = 0;
		elfc->elf64->e_shnum = 0;
		elfc->elf64->e_shstrndx = 0;
		ptr = (unsigned char *)elfc->elf64;
	}

	/* Clear content of string table */
	ptr += elfc->strtbloff;

	for(i=0; i<elfc->strtblsize; i++)
		ptr[i] = '\0';
  
}

static void
write_elf(ElfContainer *elfc, const char *out_file)
{
	int fd, flags;
	mode_t mode;
	size_t size;
	ssize_t written;
	void *ptr;  

	flags = O_CREAT|O_RDWR|O_TRUNC;
	mode = S_IRWXU|S_IRGRP|S_IWGRP;

	fd = open(out_file,flags,mode);
	if(fd == -1)
		err_exit("open()\n");

	if(elfc->type == ELF_32){
		size = elfc->elf32->e_shoff - 1;
		ptr = elfc->elf32;
	}else if(elfc->type == ELF_64){
		size = elfc->elf64->e_shoff - 1;
		ptr = elfc->elf64;
	}else
		err_exit("write_elf()\n");

	written = write(fd,ptr,size);
	if(written == 0 || written == -1)
		err_exit("write_elf() --> write()\n");

	close(fd);
  
}

int
main(int argc, char *argv[])
{
	ElfContainer *elfc_in, *elfc_out;

	if(argc != 3 || strcmp(argv[1],"--help") == 0)
		usage(argv[0]);
  
	elfc_in = build_container(argv[1]);
	write_elf(elfc_in,argv[2]);
  
	elfc_out = build_container(argv[2]);
	elfc_out->strtbloff = elfc_in->strtbloff;
	elfc_out->strtblsize = elfc_in->strtblsize;
	adjust_header(elfc_out);

	destroy_container(elfc_out);
	destroy_container(elfc_in);

    
	exit(EXIT_SUCCESS);
}
