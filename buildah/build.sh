#!/usr/bin/env bash
set -o errexit

echo "Creating new buildah container from scratch"
container=$(buildah from scratch)

echo "Mounting container filesystem"
mountpoint=$(buildah mount $container)

echo "Copying ksamlauth and making it executable"
cp ../ksamlauth $mountpoint
chmod a+x $mountpoint/ksamlauth

echo "Setting container entrypoint and UID=1000"
buildah config --user 1000:1000 $container
buildah config --entrypoint '["/ksamlauth", "daemon"]' $container


echo "Committing new container"
buildah commit --format docker $container ksamlauth:$(date +"%Y%m%d%H%M%S")

echo "Unmounting container filesystem"
buildah unmount $container