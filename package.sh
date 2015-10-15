#!/bin/sh

go get
go build

release=1
githash=`git rev-parse --short HEAD`
gitnum=`git rev-list v$release..HEAD --count`
ver=${release}.${gitnum}-${githash}

mkdir -p pkgs
archive=pkgs/docker-iptables.$ver.tar.gz

tar -czf $archive docker-iptables
