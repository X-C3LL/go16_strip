# Go16_strip
Normally I use the script [go_strip.py](https://github.com/zlowram/re-go-tooling/blob/master/r2/go_strip.py) from [@Zlowram_](https://twitter.com/Zlowram_) to patch the pclntab of binaries generated in Go to avoid information leaks (paths, function names...), but the structure in Go 1.16 has changed. I have updated the script to work for these versions. It uses radare2 via [r2pipe](https://github.com/radareorg/radare2-r2pipe)

Keep in mind that there are more places where you need to remove info **;)**

# Example
Here I use [chisel](https://github.com/jpillora/chisel) as example:

Before

![](https://raw.githubusercontent.com/X-C3LL/go16_strip/main/Captura%20de%20pantalla%20de%202021-09-08%2020-51-55.png)

After

![](https://raw.githubusercontent.com/X-C3LL/go16_strip/main/Captura%20de%20pantalla%20de%202021-09-08%2020-54-15.png)

# Author
Juan Manuel Fernández ([@TheXC3LL](https://twitter.com/TheXC3LL))
