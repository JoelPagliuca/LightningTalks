# Docker getting-started workshop

---

## Prep
Get `docker` + `docker-compose` on your machine

Either:
* Download this [minimal Linux VM](http://dl.bintray.com/vmware/photon/2.0/GA/ova/photon-custom-lsilogic-hw11-2.0-304b817.ova) that includes Docker
	* make sure you can copy stuff to this VM
* Download and install from [Docker website](https://docs.docker.com/docker-for-mac/install/)

---

## Intro
* Images vs Containers - [docs](https://docs.docker.com/v17.09/engine/userguide/storagedriver/imagesandcontainers/#images-and-layers)
![Images and Containers](docker-getting-started-workshop/assets/images/container-layers.jpg)
* `docker run -it alpine:3.7`

---

```sh
$ whoami
# root
$ uname -a
# Linux ...
$ cat /etc/alpine-release
# 3.6.2
$ exit
```