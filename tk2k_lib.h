#ifndef TURBOKOMPRESOR1999_TK2K_LIB_H
#define TURBOKOMPRESOR1999_TK2K_LIB_H

#include <jni.h>
#include "archive.h"
#include <jni.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef __cplusplus
}
#endif

#endif //TURBOKOMPRESOR1999_TK2K_LIB_H

//static Archive archive;

extern "C"
JNIEXPORT void JNICALL
Java_com_example_turbokompresor1999_ArchiveManager_load(JNIEnv* env, jobject thiz, jstring path_to_file) {
    //archive.load(path_to_file);
}
