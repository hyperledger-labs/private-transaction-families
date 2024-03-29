/*
 * Copyright (C) 2011-2018 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include "sgx_tsgxssl_t.h"
#include "tcommon.h"

#define FAKE_PIPE_READ_FD	0xFAFAFAFALL
#define FAKE_PIPE_WRITE_FD	0xFBFBFBFBLL

#define ENCLAVE_PAGE_SIZE	0x1000	// 4096 B

extern "C" {

int sgxssl_pipe (int pipefd[2])
{
	FSTART;

	// The function is used only by the engines/e_dasync.c (dummy async engine).
	// Adding fake implementation only to be able to distinguish pipe read/write from socket read/write
	pipefd[0] = FAKE_PIPE_READ_FD;
	pipefd[1] = FAKE_PIPE_WRITE_FD;

	FEND;

	// On error, -1 is returned, and errno is set appropriately
	return 0;
}

size_t sgxssl_write (int fd, const void *buf, size_t n)
{
	FSTART;

	if (fd == FAKE_PIPE_WRITE_FD) {
		// With pipes the function is used only by the engines/e_dasync.c (dummy async engine).
		SGX_UNSUPPORTED_FUNCTION(SET_ERRNO);

		FEND;
		// On error, -1 is returned, and errno is set appropriately
		return -1;
	}

	size_t retval = 0 ;
	sgx_status_t ret = u_sgxssl_write(&retval, fd, buf, n);
	if (ret != SGX_SUCCESS) 
	{
		FEND;
		return 0;
	}
	FEND;

	return retval;
}

size_t sgxssl_read(int fd, void *buf, size_t count)
{
	FSTART;

	if (fd == FAKE_PIPE_READ_FD) {
		// With pipes the function is used only by the engines/e_dasync.c (dummy async engine).
		SGX_UNSUPPORTED_FUNCTION(SET_ERRNO);

		FEND;
		// On error, -1 is returned, and errno is set appropriately
		return -1;
	}

	size_t retval = 0 ;
	sgx_status_t ret = u_sgxssl_read(&retval, fd, buf, count);
	if (ret != SGX_SUCCESS) 
	{
		FEND;
		return 0;
	}
	FEND;

	return retval;
}

// TODO
int sgxssl_close(int fd)
{
	FSTART;

	if (fd == FAKE_PIPE_READ_FD ||
		fd == FAKE_PIPE_WRITE_FD) {
		// With pipes the function is used only by the engines/e_dasync.c (dummy async engine).
		SGX_UNSUPPORTED_FUNCTION(SET_ERRNO);

		FEND;
		// On error, -1 is returned, and errno is set appropriately
		return -1;
	}

	int retval = 0 ;
	sgx_status_t ret = u_sgxssl_close(&retval, fd);
	if (ret != SGX_SUCCESS) 
	{
		FEND;
		return 0;
	}
	FEND;

	return retval;
}

long sgxssl_sysconf(int name)
{
	FSTART;

	// Used by mem_sec.c
	if (name == _SC_PAGESIZE) {
		return ENCLAVE_PAGE_SIZE;
	}

	SGX_UNREACHABLE_CODE(SET_ERRNO);
	FEND;

	return -1;
}


} // extern "C"
