cd crashes/deduped
find * | parallel -x afl-tmin -i {} -o ../minimized/crash{#} -- ../../build/main_fuzz @@
cd ../minimized
ls