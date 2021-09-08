#!/usr/bin/env python

# go16_strip - based on https://github.com/zlowram/re-go-tooling/blob/master/r2/go_strip.py (@zlowram_)
# Updated following https://github.com/golang/go/blob/master/src/debug/gosym/pclntab.go#L229
# Author: Juan Manuel Fernández (@TheXC3LL)


import sys
import re
import r2pipe

class Go16BinaryStripper():
        def __init__(self, binary_path):
                self.r2 = r2pipe.open(binary_path, ['-w', '-2'])
                self.ptrsize = 0
                self.nFunctab = 0
                self.filetab = 0
                self.nFiletab = 0
                self.funcnametab = 0
                self.first_entry = 0
                self.last_name = 0
                gopclntab_addr = self.r2.cmdj('/xj faffffff0000')[0]['offset']
                self.r2.cmd('s {}'.format(gopclntab_addr))
                self.pclntab_baseaddr = int(self.r2.cmd('s'), 16)
                print("[+] pclntab base address: " + str(hex(self.pclntab_baseaddr)))
                self._read_header()


        def strip(self):
            print("[+] Starting to parse & patch function table")
            for _ in range(0, self.nFunctab):
                self._seek(self.first_entry + _ * self.ptrsize * 2 + 8)
                offset_struct = self._read_bytes(self.ptrsize)
                struct_ptr = self.first_entry + offset_struct
                self._seek(struct_ptr + self.ptrsize)
                offset_name = self._read_bytes(4)
                name_address = offset_name + self.funcnametab
                name = self._read_string_at(name_address)
                self._write_string_at('00' * len(name), name_address)
            print("[+] Starting to parse & patch file table")
            for _ in range(0, self.nFiletab):
                name = self._read_string_at(self.last_name)
                self._write_string_at('00' * len(name), self.last_name)
                self.last_name = self.last_name + len(name)



        def _read_header(self):
                self._skip_bytes(7) # magic header + 3
                self.ptrsize = self._read_bytes(1)
                print("[+] PtrSize: " + str(self.ptrsize))
                self.nFunctab = self._read_bytes(4)
                print("[+] Table Size: " + str(self.nFunctab))
                self._seek(self.pclntab_baseaddr + 8 + self.ptrsize)
                self.nFiletab = self._read_bytes(4)
                print("[+] Filetab Size: " + str(self.nFunctab))
                self._seek(self.pclntab_baseaddr + 8 + 2 * self.ptrsize)
                self.funcnametab = self._read_bytes(self.ptrsize) + self.pclntab_baseaddr
                print("[+] Funcnametab: " + str(hex(self.funcnametab)))
                self._seek(self.pclntab_baseaddr + 8 + 4 * self.ptrsize)
                self.filetab = self._read_bytes(self.ptrsize) + self.pclntab_baseaddr
                print("[+] Filetab: " + str(hex(self.filetab)))
                self._seek(self.pclntab_baseaddr + 8 + 6 * self.ptrsize)
                self.first_entry = self._read_bytes(self.ptrsize) + self.pclntab_baseaddr
                print("[+] First entry: " + str(hex(self.first_entry)))
                self.last_name = self.filetab

        def _read_bytes(self, n):
                value = self.r2.cmdj('pfj n{}'.format(n))[0]['value']
                self.r2.cmd('s +{}'.format(n))
                return value

        def _read_string_at(self, addr):
                return self.r2.cmd('ps @ {}'.format(addr))

        def _write_string_at(self, string, addr):
                    return self.r2.cmd('wx {} @ {}'.format(string, addr))

        def _skip_bytes(self, n):
                self.r2.cmd('s +{}'.format(n))

        def _seek(self, addr):
                self.r2.cmd('s {}'.format(addr))

if __name__ == '__main__':
        go_stripper = Go16BinaryStripper(sys.argv[1])
        go_stripper.strip()
