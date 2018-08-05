# Docker getting-started workshop

---

## Prep
Get @color[#0DB7ED](`docker`) +  @color[#0DB7ED](`docker-compose`) on your machine

* Download this [minimal Linux VM](http://dl.bintray.com/vmware/photon/2.0/GA/ova/photon-custom-lsilogic-hw11-2.0-304b817.ova) that includes Docker
	* make sure you can copy stuff to this VM
OR
* Download and install from [Docker website](https://docs.docker.com/docker-for-mac/install/)

Note:

- aufs - a union file system

---

## @fs[hand-paper] Intro
* Images vs Containers - [docs](https://docs.docker.com/v17.09/engine/userguide/storagedriver/imagesandcontainers/#images-and-layers)

![Images and Containers](docker-getting-started-workshop/assets/images/container-layers.jpg)

---

## @fa[play-circle](`docker run -it alpine:3.7`)

@ul

- `$ whoami`
- `> root`
- 

@ulend
```bash


$ uname -a
# Linux ...
$ cat /etc/alpine-release
# 3.6.2
$ exit
```