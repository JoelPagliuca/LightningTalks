# Docker getting-started workshop

---

### @fa[laptop](Prep)
Get @color[#0DB7ED](`docker`) +  @color[#0DB7ED](`docker-compose`) on your machine

* Download this [minimal Linux VM](http://dl.bintray.com/vmware/photon/2.0/GA/ova/photon-custom-lsilogic-hw11-2.0-304b817.ova) that includes Docker
	* make sure you can copy stuff to this VM
OR
* Download and install from [Docker website](https://docs.docker.com/docker-for-mac/install/)

Note:

- aufs - a union file system

---

### @fs[docker](Intro)
* Images vs Containers - [docs](https://docs.docker.com/v17.09/engine/userguide/storagedriver/imagesandcontainers/#images-and-layers)

![Images and Containers](docker-getting-started-workshop/assets/images/container-layers.jpg)

---

### @fa[play-circle](`docker run -it alpine:3.7`)

@snap[west]
```sh
$ whoami
$ uname -a
$ cat /etc/alpine-release
$ exit
```
@snapend

@snap[east]
```sh
> root
> Linux ...
> 3.6.2
# your terminal
```
@snapend