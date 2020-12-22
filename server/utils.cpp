#include <fstream>
#include <sstream>
#include <system_error>
#include <vector>

#include <cstring>
#include <cstdio>
#include <cerrno>

#include <sys/types.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/wait.h>

#include "utils.h"

namespace my {

std::string get_file_contents(const char* filename) {
	std::ifstream in(filename, std::ios::in | std::ios::binary);
	if (!in) {
		throw std::system_error(errno, std::generic_category());
	}
	std::ostringstream contents;
	contents << in.rdbuf();
	in.close();
	return contents.str();
}

void set_file_contents(const char* filename, std::string contents) {
	std::ofstream out(filename, std::ios::out | std::ios::trunc | std::ios::binary);
	if (!out) {
		throw std::system_error(errno, std::generic_category());
	}
	out << contents;
	out.close();
}

/*
std::string create_tmp_file(std::string contents) {
	const std::string tmp_filename = std::tmpnam(nullptr);
	my::set_file_contents(tmp_filename.c_str(), contents);
	return tmp_filename;
}
*/

char* hash_password(const char* password, const char* hash) {
	return crypt(password, hash);
}

bool verify_password(const std::string& password, const std::string& hash) {
	char* new_hash = crypt(password.c_str(), hash.c_str());
	if (new_hash == NULL) {
		throw std::system_error(errno, std::generic_category());
	}
	return (std::strncmp(new_hash, hash.c_str(), hash.size()) == 0);
}

void write_certificate(std::string cert, std::string username) {
	std::string filename = "./mailbox/users/" + username + "/certs/" + username + ".cert.pem";
	set_file_contents(filename.c_str(), cert);
}

std::string sign_client_csr(const std::string& csr) {
	
	int saved_errno = -1;
	std::string saved_errmsg;
	
	pid_t pid, wpid;
	int pipefd_out[2], pipefd_in[2];
	std::string tmp = std::tmpnam(nullptr);
	
	if (pipe(pipefd_out) < 0) {
		saved_errno = errno;
		goto pp_out_exit;
	}
	if (pipe(pipefd_in) < 0) {
		saved_errno = errno;
		goto pp_in_exit;
	}
	
	pid = fork();
	if (pid < 0) {
		saved_errno = errno;
		goto fork_exit;
	}
	
	if (pid == 0) {
		// Child Process
		close(STDIN_FILENO);
		close(STDOUT_FILENO);
		close(STDERR_FILENO); // so that nothing is printed
		if (dup2(pipefd_out[1], STDOUT_FILENO) < 0) {
			saved_errmsg = "sign_client_csr child dup2 stdout";
			goto child_exit;
		}
		if (dup2(pipefd_in[0], STDIN_FILENO) < 0) {
			saved_errmsg = "sign_client_csr child dup2 stdin";
			goto child_exit;
		}
		
		// close unused fds
		close(pipefd_out[0]);
		close(pipefd_in[1]);

		// write to temp file so that openssl can read
		int read_size, res;
		char buf[1024];
		int tmp_file = open(tmp.c_str(), O_CREAT | O_WRONLY);
		while((read_size = read(STDIN_FILENO, buf, sizeof(buf))) > 0) {
			res = write(tmp_file, buf, read_size);
		}

		close(tmp_file);

		fprintf(stderr, "read file\n");
		
		char exe_path[] = "openssl";
		execlp(
			exe_path, exe_path, "ca", \
			"-config", "serv_conf/client_config.cnf", \
			"-extensions", "usr_cert", \
			"-days", "375", "-notext", \
			"-md", "sha256", "-batch", \
			"-in", tmp.c_str(), \
			"-passin", "file:pwds/ica_pass", \
			NULL);
		
		// exec failed!
		saved_errmsg = "sign_client_csr child execv";
		goto child_exit;
	} else {
		// close unused fds
		close(pipefd_in[0]);
		close(pipefd_out[1]);

		// write csr to child
		const char *csr_buf = csr.c_str();
		int len = csr.length();
		write(pipefd_in[1], csr_buf, len);
		close(pipefd_in[1]);

		// read signed cert from child
		std::string signed_cert;
		char buf[1024];
		ssize_t read_size;
		while((read_size = read(pipefd_out[0], buf, sizeof(buf))) > 0) {
			signed_cert += std::string(buf, buf + read_size);
		}
	
		// close remaining fds
		close(pipefd_in[1]);
		close(pipefd_out[0]);
	
		if (read_size < 0) {
			saved_errmsg = "read cert from child failed!";
			goto read_exit;
		}
	
		int wstatus;
		wpid = wait(&wstatus);
		if (wpid < 0) {
			saved_errno = errno;
			goto wait_exit;
		} else if (wpid != pid) {
			saved_errmsg = "waited on the wrong child!";
			goto wait_exit;
		} else if (!WIFEXITED(wstatus) || WEXITSTATUS(wstatus) != 0) {
			saved_errmsg = "child terminated abnormally!";
			goto wait_exit;
		}
	
		// child completed normally

		// remove tempfile
		remove(tmp.c_str());
	
		return signed_cert;
	}

wait_exit:
fork_exit:
	close(pipefd_in[0]);
	close(pipefd_in[1]);
pp_in_exit:
	close(pipefd_out[0]);
	close(pipefd_out[1]);
pp_out_exit:
read_exit:
	if (saved_errno > 0) {
		throw std::system_error(saved_errno, std::generic_category());
	} else {
		throw std::runtime_error(saved_errmsg);
	}

child_exit:
	std::perror(saved_errmsg.c_str());
	exit(1);
}

void fork_exec(const char *path, char *const argv[]) {
	pid_t pid = fork(), wpid;
	if (pid < 0) {
		throw std::system_error(errno, std::generic_category());
	}
	
	if (pid == 0) {
		execv(path, argv);
		throw std::system_error(errno, std::generic_category());
	} else {
		int wstatus;
		wpid = wait(&wstatus);
		if (wpid < 0) {
			throw std::system_error(errno, std::generic_category());
		} else if (wpid != pid) {
			throw std::runtime_error("waited on the wrong child!");
		} else if (!WIFEXITED(wstatus) || WEXITSTATUS(wstatus) != 0) {
			throw std::runtime_error("child terminated abnormally!");
		} else {
			// child completed normally
		}
	}
}

}