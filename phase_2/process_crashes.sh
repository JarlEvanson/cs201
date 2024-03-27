set -e
rm -r crashes
mkdir -p crashes/raw crashes/deduped crashes/minimized
find ramdisk -regex "ramdisk/[a-z]+-wks001/crashes/.+" -not -regex .+README.+ | parallel cp {} crashes/raw/crash{#}
afl-cmin -i crashes/raw/ -o crashes/deduped/ -CA -- ./build/main_fuzz @@
find crashes/deduped/ -not -regex crashes/deduped/ | parallel afl-tmin -i {} -o crashes/minimized/crash{#} -- build/main_fuzz @@