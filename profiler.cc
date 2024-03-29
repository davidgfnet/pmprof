
// Copyright 2022 - David Guillen Fandos <david@davidgf.net>
// Please assume GPL license unless otherwise specified.

// Poor man's profiler
// Program counter sampling based profiler
// Given a process Id it will make use of the ptrace API to sample the
// program counter and determine what is the program executing.
// This requires that libraries and programs have symbols (in ELF file)

#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <libelf.h>
#include <gelf.h>
#include <dirent.h>

#include <iostream>
#include <map>
#include <vector>
#include <unordered_map>
#include <string>
#include <cstring>

#ifdef __x86_64__
  #define REG_CONTEXT_TYPE struct user_regs_struct
  #define GetPC(regs) (uint64_t)((regs).rip)
#elif defined(__i386__) || defined(i386)
  #define REG_CONTEXT_TYPE struct user_regs_struct
  #define GetPC(regs) (uint32_t)((regs).eip)
#elif defined(__aarch64__)
  #define REG_CONTEXT_TYPE struct user_regs_struct
  #define GetPC(regs) (uint64_t)((regs).pc)
#elif defined(__arm__)
  #define REG_CONTEXT_TYPE struct user_regs
  #define GetPC(regs) (uint32_t)((regs).uregs[15])
#endif

class SymFile {
private:
	struct t_symbol {
		std::string name;
		uint64_t size;
	};
	std::map<uint64_t, t_symbol> symbols;

public:
	uint64_t startaddr, endaddr;
	std::string filename;

	std::string findSym(uint64_t addr) {
		auto it = symbols.upper_bound(addr);
		if (it == symbols.end())
			return "???";
		if (it != symbols.begin())
			it--;
		if (addr <= it->first + it->second.size)
			return it->second.name;
		return "???";
	}

	SymFile(const char *fn, uint64_t baseaddr, uint64_t endaddr) {
		this->filename = fn;
		this->startaddr = baseaddr;
		this->endaddr = endaddr;

		struct stat statbuf;
		if (stat(fn, &statbuf))
			return;

		// Only parse real files! There are lots of mem mapped files and weird stuff
		if (!S_ISREG(statbuf.st_mode))
			return;

		int fd = open(fn, O_RDONLY, 0);
		if (fd < 0)
			return;

		elf_version(EV_CURRENT);
		Elf *elf = elf_begin(fd, ELF_C_READ, NULL);
		if (!elf) {
			close(fd);
			return;
		}
		GElf_Shdr shdr;
		Elf_Scn *scn = NULL;
		while ((scn = elf_nextscn(elf, scn)) != NULL) {
			gelf_getshdr(scn, &shdr);
			if (shdr.sh_type == SHT_SYMTAB)
				break;
		}
		if (!scn) {
			close(fd);
			return;
		}

		std::map<uint64_t, uint64_t, std::greater<uint64_t>> progs;
		size_t numpgm = 0;
		elf_getphdrnum(elf, &numpgm);
		for (unsigned i = 0; i < numpgm; i++) {
			GElf_Phdr phdr;
			gelf_getphdr(elf, i, &phdr);
			// Only load sections are relevant
			if (phdr.p_type == PT_LOAD)
				progs[phdr.p_vaddr] = phdr.p_memsz;
		}

		Elf_Data *data = elf_getdata(scn, NULL);
		unsigned count = shdr.sh_size / shdr.sh_entsize;

		for (unsigned i = 0; i < count; ++i) {
			GElf_Sym sym;
			gelf_getsym(data, i, &sym);
			unsigned symtype = GELF_ST_TYPE(sym.st_info);
			if (symtype != STT_FUNC)
				continue;
			uint64_t symaddr = sym.st_value;
			// Find the program section at this address
			auto it = progs.lower_bound(symaddr);
			if (it == progs.end())
				continue;
			if (symaddr > it->first + it->second)
				continue;
			// Calculate the final symbol address
			uint64_t absaddr = symaddr + baseaddr - it->first;
			if (absaddr > endaddr)
				continue;
			std::string symname = elf_strptr(elf, shdr.sh_link, sym.st_name);
			if (symbols.count(absaddr)) {
				symbols[absaddr].size = std::max(sym.st_size, symbols[absaddr].size);
				symbols[absaddr].name += " / " + symname;
			} else {
				symbols[absaddr] = t_symbol{symname, sym.st_size};
			}
		}
		elf_end(elf);
		close(fd);
	}
};

class SymDatabase {
public:
	std::map<uint64_t, SymFile> maps;

	// Find the symbol in the sym files
	SymFile *findSymFile(uint64_t addr) {
		auto it = maps.upper_bound(addr);
		if (it != maps.begin())
			it--;

		return &(it->second);
	}
};

bool working = true;
void sig_handler(int signo) {
	working = false;
}

int main(int argc, char ** argv) {
	if (argc <= 1 || !strcmp(argv[1], "-h")) {
		printf("Usage: %s [-t] [-s us] PID\n", argv[0]);
		printf("  -t : Only attach to a single thread (default try to attach to all threads)\n");
		printf("  -s : Sample period (in microseconds), default is 10ms (10.000us)\n");
		return 1;
	}

	int sthread = 0, sampleus = 10000;
	for (unsigned i = 1; i < argc - 1; i++) {
		if (!strcmp(argv[i], "-t"))
			sthread = 1;
		if (!strcmp(argv[i], "-s"))
			sampleus = atoi(argv[++i]);
	}
	pid_t pid = atoi(argv[argc-1]);
	signal(SIGINT, sig_handler);

	// Get a list of all tasks for this PID
	std::vector<pid_t> tasks;
	if (sthread)
		tasks.push_back(pid);
	else {
		std::string tdir = "/proc/" + std::to_string(pid) + "/task";
		DIR *d = opendir(tdir.c_str());
		if (d) {
			struct dirent *entry;
			while ((entry = readdir(d)) != NULL)
				if (entry->d_name[0] != '.')
					tasks.push_back(atoi(entry->d_name));
			closedir(d);
		}
		if (tasks.empty()) {
			fprintf(stderr, "Could not find tasks at /proc/%u/task\n", pid);
			return -1;
		}
	}

	// Repeat this for every task ID
	std::unordered_map<pid_t, SymDatabase> symdbs;
	for (pid_t taskid : tasks) {
		// Parse /proc/maps to get the process memory map
		std::string mapfile = "/proc/" + std::to_string(pid) + "/maps";
		FILE *fd = fopen(mapfile.c_str(), "r");
		if (!fd) {
			fprintf(stderr, "Skipping taskID %u, could not find /proc/%u\n", pid, pid);
			continue;
		}

		char line[2048];
		while (fgets(line, sizeof(line), fd)) {
			uint64_t startva, endva, foffset, foo;
			char c1, c2, c3, c4, c5, c6, c7, c8;
			char filen[2048] = {0};
			sscanf(line, "%llx-%llx %c%c%c%c %llx %c%c:%c%c %llu %s",
				&startva, &endva, &c1, &c2, &c3, &c4, &foffset,
				&c5, &c6, &c7, &c8, &foo, filen);
			symdbs[taskid].maps.emplace(startva, SymFile(filen, startva, endva));
		}
	}

	if (symdbs.empty()) {
		fprintf(stderr, "Could not load any task, aborting ...\n");
		return 1;
	}

	uint64_t totalsamples = 0;
	std::unordered_map<std::string, uint64_t> samples;
	for (pid_t taskid : tasks)
		ptrace(PTRACE_SEIZE, taskid, NULL, NULL);

	unsigned rr = 0;
	while (working) {
		pid_t ctask = tasks[rr];
		REG_CONTEXT_TYPE regs;
		ptrace(PTRACE_INTERRUPT, ctask, NULL, NULL);
		while (true) {
			int stat;
			waitpid(ctask, &stat, __WALL);
			if (WIFSTOPPED(stat))
				break;
		}
		if (ptrace(PTRACE_GETREGS, ctask, NULL, &regs) >= 0) {
			uint64_t pc = GetPC(regs);
			auto symfile = symdbs[ctask].findSymFile(pc);
			std::string symbol = symfile->findSym(pc) + " [" + symfile->filename + "]";
			samples[symbol]++;
			totalsamples++;
		}
		ptrace(PTRACE_CONT, ctask, NULL, NULL);
		usleep(sampleus);
		rr = (rr + 1) % tasks.size();
	}

	for (pid_t taskid : tasks)
		ptrace(PTRACE_DETACH, taskid, NULL, NULL);

	std::map<uint64_t, std::string> osamples;
	for (auto it : samples)
		osamples.emplace(-it.second, it.first);
	printf("Results for %llu samples captured\n", totalsamples);
	for (auto it : osamples)
		printf("%.02f%% %s\n", (-100 * it.first) / float(totalsamples), it.second.c_str());
}

