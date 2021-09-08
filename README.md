# Go16_strip
Normally I use the script [go_strip.py](https://github.com/zlowram/re-go-tooling/blob/master/r2/go_strip.py) from [@Zlowram_](https://twitter.com/Zlowram_) to patch the pclntab of binaries generated in Go to avoid information leaks (paths, function names...), but the structure in Go 1.16 has changed. I have updated the script to work for these versions. It uses radare2 via [r2pipe](https://github.com/radareorg/radare2-r2pipe)

# Example
Here I use [chisel](https://github.com/jpillora/chisel) as example:
Before:

After:
