set -e
make clean
make FINALPACKAGE=1
cp -Rv "./.theos/obj/libsandy.dylib" "$THEOS/lib"
cp -v "./libSandy.h" "$THEOS/include"
echo "Successfully installed libSandy"