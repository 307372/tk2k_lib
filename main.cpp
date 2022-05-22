#include <iostream>
#include "archive.h"

int main() {
    Archive archive;
    archive.load("/home/pc/Desktop/asdf.tk2k");
    archive.recursive_print();
    return 0;
}
